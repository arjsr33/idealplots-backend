// ================================================================
// BACKEND/ROUTES/USERS.JS - USER PROFILE MANAGEMENT ONLY
// Clean separation: Only user's own profile operations
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');

// Import middleware and services
const { authenticateToken, hashPassword, comparePassword } = require('../middleware/auth');
const { handleProfileImageUpload, updateUserProfileImage } = require('../middleware/upload');
const { asyncHandler, ValidationError, NotFoundError, DuplicateError, AuthenticationError } = require('../middleware/errorHandler');
const { audit } = require('../middleware/audit'); // ✅ AUDIT MIDDLEWARE
const { executeQuery, executeTransaction } = require('../database/connection');

// Import services
const userService = require('../services/userService');
const notificationService = require('../services/notificationService');

const router = express.Router();

// ================================================================
// RATE LIMITING
// ================================================================

const profileUpdateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { success: false, error: 'Too many profile update attempts, please try again later.' }
});

const passwordChangeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { success: false, error: 'Too many password change attempts, please try again later.' }
});

// ================================================================
// VALIDATION RULES
// ================================================================

const profileUpdateValidation = [
  body('name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('phone').optional().matches(/^\+?91[6-9]\d{9}$/),
  body('gender').optional().isIn(['male', 'female', 'other']),
  body('date_of_birth').optional().isISO8601(),
  body('address').optional().isLength({ max: 1000 }).trim(),
  body('city').optional().isLength({ max: 100 }).trim(),
  body('state').optional().isLength({ max: 100 }).trim(),
  body('pincode').optional().matches(/^\d{6}$/),
  body('is_buyer').optional().isBoolean(),
  body('is_seller').optional().isBoolean(),
  body('preferred_property_types').optional().custom((value) => {
    const validTypes = ['villa', 'apartment', 'house', 'plot', 'commercial'];
    return !value || (Array.isArray(value) && value.every(type => validTypes.includes(type)));
  }),
  body('budget_min').optional().isDecimal({ decimal_digits: '0,2' }),
  body('budget_max').optional().isDecimal({ decimal_digits: '0,2' }),
  body('preferred_cities').optional().custom((value) => {
    const validCities = ['Thiruvananthapuram', 'Kochi', 'Kozhikode', 'Thrissur', 'Kollam', 'Palakkad', 'Alappuzha', 'Kottayam', 'Kannur', 'Kasaragod', 'Malappuram', 'Pathanamthitta', 'Idukki', 'Wayanad'];
    return !value || (Array.isArray(value) && value.every(city => validCities.includes(city)));
  }),
  body('preferred_bedrooms').optional().custom((value) => {
    const validBedrooms = ['1', '2', '3', '4', '5+'];
    return !value || (Array.isArray(value) && value.every(bedroom => validBedrooms.includes(bedroom)));
  }),
  body('specialization').optional().isLength({ max: 1000 }).trim(),
  body('agent_bio').optional().isLength({ max: 2000 }).trim()
];

const passwordChangeValidation = [
  body('current_password').notEmpty().withMessage('Current password is required'),
  body('new_password').isLength({ min: 8, max: 128 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).withMessage('New password must be 8+ chars with uppercase, lowercase, number, and special character'),
  body('confirm_password').custom((value, { req }) => {
    if (value !== req.body.new_password) {
      throw new Error('Password confirmation does not match');
    }
    return true;
  })
];

// ================================================================
// USER PROFILE ROUTES
// ================================================================

/**
 * Get current user's profile
 * GET /api/users/profile
 */
router.get('/profile',
  authenticateToken,
  audit.viewProfile,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const userProfile = await userService.getUserProfile(userId);

    res.json({
      success: true,
      data: { user: userProfile }
    });
  })
);

/**
 * Update user profile
 * PUT /api/users/profile
 */
router.put('/profile',
  authenticateToken,
  profileUpdateLimiter,
  profileUpdateValidation,
  audit.updateProfile,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const updateData = req.body;

    const result = await executeTransaction(async (connection) => {
      const [currentUsers] = await connection.execute('SELECT * FROM users WHERE id = ?', [userId]);
      if (currentUsers.length === 0) {
        throw new NotFoundError('User not found');
      }

      const currentUser = currentUsers[0];

      // Check for phone number conflicts
      if (updateData.phone && updateData.phone !== currentUser.phone) {
        const [phoneExists] = await connection.execute('SELECT id FROM users WHERE phone = ? AND id != ?', [updateData.phone, userId]);
        if (phoneExists.length > 0) {
          throw new DuplicateError('Phone number already in use');
        }
      }

      // Build update query dynamically
      const allowedFields = ['name', 'phone', 'gender', 'date_of_birth', 'address', 'city', 'state', 'pincode', 'is_buyer', 'is_seller', 'preferred_property_types', 'budget_min', 'budget_max', 'preferred_cities', 'preferred_bedrooms'];

      if (currentUser.user_type === 'agent') {
        allowedFields.push('specialization', 'agent_bio');
      }

      const updateFields = [];
      const updateValues = [];

      Object.entries(updateData).forEach(([key, value]) => {
        if (allowedFields.includes(key) && value !== undefined) {
          if (Array.isArray(value)) {
            updateFields.push(`${key} = ?`);
            updateValues.push(value.join(','));
          } else {
            updateFields.push(`${key} = ?`);
            updateValues.push(value);
          }
        }
      });

      if (updateFields.length === 0) {
        throw new ValidationError('No valid fields to update');
      }

      updateFields.push('updated_at = NOW()');
      updateValues.push(userId);

      await connection.execute(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, updateValues);

      // If phone number changed, reset phone verification
      if (updateData.phone && updateData.phone !== currentUser.phone) {
        await connection.execute('UPDATE users SET phone_verified_at = NULL, phone_verification_code = NULL WHERE id = ?', [userId]);
        try {
          await notificationService.sendVerificationSMS(userId);
        } catch (error) {
          console.error('Failed to send phone verification:', error);
        }
      }

      const updatedProfile = await userService.getUserProfile(userId);

      return {
        user: updatedProfile,
        phoneVerificationSent: updateData.phone && updateData.phone !== currentUser.phone
      };
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: result
    });
  })
);

/**
 * Change user password
 * PUT /api/users/password
 */
router.put('/password',
  authenticateToken,
  passwordChangeLimiter,
  passwordChangeValidation,
  audit.changePassword,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const { current_password, new_password } = req.body;

    await executeTransaction(async (connection) => {
      const [users] = await connection.execute('SELECT id, name, email, password FROM users WHERE id = ?', [userId]);
      if (users.length === 0) {
        throw new NotFoundError('User not found');
      }

      const user = users[0];
      const isCurrentPasswordValid = await comparePassword(current_password, user.password);
      
      if (!isCurrentPasswordValid) {
        throw new AuthenticationError('Current password is incorrect');
      }

      const hashedNewPassword = await hashPassword(new_password);
      await connection.execute('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [hashedNewPassword, userId]);
    });

    res.json({
      success: true,
      message: 'Password changed successfully',
      data: { changedAt: new Date().toISOString() }
    });
  })
);

/**
 * Update user preferences
 * PUT /api/users/preferences
 */
router.put('/preferences',
  authenticateToken,
  profileUpdateLimiter,
  body('preferred_property_types').optional().isArray(),
  body('budget_min').optional().isDecimal(),
  body('budget_max').optional().isDecimal(),
  body('preferred_cities').optional().isArray(),
  body('preferred_bedrooms').optional().isArray(),
  audit.custom('preferences_update'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const preferences = req.body;

    const result = await executeTransaction(async (connection) => {
      const updateFields = [];
      const updateValues = [];

      if (preferences.preferred_property_types !== undefined) {
        updateFields.push('preferred_property_types = ?');
        updateValues.push(Array.isArray(preferences.preferred_property_types) ? preferences.preferred_property_types.join(',') : preferences.preferred_property_types);
      }

      if (preferences.budget_min !== undefined) {
        updateFields.push('budget_min = ?');
        updateValues.push(preferences.budget_min);
      }

      if (preferences.budget_max !== undefined) {
        updateFields.push('budget_max = ?');
        updateValues.push(preferences.budget_max);
      }

      if (preferences.preferred_cities !== undefined) {
        updateFields.push('preferred_cities = ?');
        updateValues.push(Array.isArray(preferences.preferred_cities) ? preferences.preferred_cities.join(',') : preferences.preferred_cities);
      }

      if (preferences.preferred_bedrooms !== undefined) {
        updateFields.push('preferred_bedrooms = ?');
        updateValues.push(Array.isArray(preferences.preferred_bedrooms) ? preferences.preferred_bedrooms.join(',') : preferences.preferred_bedrooms);
      }

      if (updateFields.length === 0) {
        throw new ValidationError('No preferences provided to update');
      }

      updateFields.push('updated_at = NOW()');
      updateValues.push(userId);

      await connection.execute(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, updateValues);

      return {
        updatedPreferences: preferences,
        updatedAt: new Date().toISOString()
      };
    });

    res.json({
      success: true,
      message: 'Preferences updated successfully',
      data: result
    });
  })
);

// ================================================================
// USER DASHBOARD AND DATA
// ================================================================

/**
 * Get user dashboard data
 * GET /api/users/dashboard
 */
router.get('/dashboard',
  authenticateToken,
  audit.viewDashboard,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const [dashboardData] = await executeQuery('SELECT * FROM user_dashboard_view WHERE id = ?', [userId]);
    if (dashboardData.length === 0) {
      throw new NotFoundError('User dashboard data not found');
    }

    const dashboard = dashboardData[0];

    const [recentActivity] = await executeQuery(`
      SELECT 'property_listed' as activity_type, pl.id as item_id, pl.title as item_title, pl.created_at as activity_date
      FROM property_listings pl WHERE pl.owner_id = ?
      UNION ALL
      SELECT 'property_favorited' as activity_type, pl.id as item_id, pl.title as item_title, uf.created_at as activity_date
      FROM user_favorites uf JOIN property_listings pl ON uf.property_id = pl.id WHERE uf.user_id = ?
      UNION ALL
      SELECT 'enquiry_submitted' as activity_type, e.id as item_id, e.ticket_number as item_title, e.created_at as activity_date
      FROM enquiries e WHERE e.user_id = ?
      ORDER BY activity_date DESC LIMIT 10
    `, [userId, userId, userId]);

    res.json({
      success: true,
      data: { dashboard, recent_activity: recentActivity }
    });
  })
);

// ================================================================
// USER ENQUIRIES
// ================================================================

/**
 * Get user's enquiries
 * GET /api/users/enquiries
 */
router.get('/enquiries',
  authenticateToken,
  audit.viewEnquiries,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { page = 1, limit = 10, status } = req.query;
    const offset = (page - 1) * limit;

    let baseQuery = `
      SELECT e.id, e.ticket_number, e.requirements, e.status, e.created_at, e.property_id, e.property_title, e.assigned_to,
             agent.name as agent_name, agent.phone as agent_phone, agent.email as agent_email
      FROM enquiries e
      LEFT JOIN users agent ON e.assigned_to = agent.id
      WHERE e.user_id = ?
    `;

    const queryParams = [userId];

    if (status) {
      baseQuery += ' AND e.status = ?';
      queryParams.push(status);
    }

    baseQuery += ' ORDER BY e.created_at DESC LIMIT ? OFFSET ?';
    queryParams.push(parseInt(limit), offset);

    const enquiries = await executeQuery(baseQuery, queryParams);

    let countQuery = 'SELECT COUNT(*) as total FROM enquiries WHERE user_id = ?';
    const countParams = [userId];

    if (status) {
      countQuery += ' AND status = ?';
      countParams.push(status);
    }

    const [countResult] = await executeQuery(countQuery, countParams);
    const total = countResult[0].total;

    res.json({
      success: true,
      data: {
        enquiries,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1
        }
      }
    });
  })
);

/**
 * Get specific enquiry details
 * GET /api/users/enquiries/:id
 */
router.get('/enquiries/:id',
  authenticateToken,
  param('id').isInt().withMessage('Valid enquiry ID required'),
  audit.custom('view_enquiry_details'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const enquiryId = parseInt(req.params.id);

    const [enquiries] = await executeQuery(`
      SELECT e.*, agent.name as agent_name, agent.phone as agent_phone, agent.email as agent_email, agent.agency_name,
             pl.title as property_title, pl.listing_id, pl.property_type, pl.price, pl.city, pl.location
      FROM enquiries e
      LEFT JOIN users agent ON e.assigned_to = agent.id
      LEFT JOIN property_listings pl ON e.property_id = pl.id
      WHERE e.id = ? AND e.user_id = ?
    `, [enquiryId, userId]);

    if (enquiries.length === 0) {
      throw new NotFoundError('Enquiry not found');
    }

    const enquiry = enquiries[0];

    const [notes] = await executeQuery(`
      SELECT en.id, en.note, en.note_type, en.communication_method, en.next_follow_up_date, en.created_at,
             u.name as created_by_name, u.user_type as created_by_type
      FROM enquiry_notes en
      JOIN users u ON en.user_id = u.id
      WHERE en.enquiry_id = ?
      ORDER BY en.created_at DESC
    `, [enquiryId]);

    res.json({
      success: true,
      data: { enquiry, notes }
    });
  })
);

// ================================================================
// PROFILE IMAGE MANAGEMENT
// ================================================================

/**
 * Upload profile image
 * POST /api/users/profile/image
 */
router.post('/profile/image',
  authenticateToken,
  handleProfileImageUpload,
  audit.custom('profile_image_upload'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    if (!req.processedProfileImage) {
      throw new ValidationError('No image file processed');
    }

    const result = await updateUserProfileImage(userId, req.processedProfileImage, req);

    res.json({
      success: true,
      message: 'Profile image updated successfully',
      data: result
    });
  })
);

/**
 * Delete profile image
 * DELETE /api/users/profile/image
 */
router.delete('/profile/image',
  authenticateToken,
  audit.custom('profile_image_delete'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const result = await executeTransaction(async (connection) => {
      const [users] = await connection.execute('SELECT profile_image FROM users WHERE id = ?', [userId]);
      if (users.length === 0) {
        throw new NotFoundError('User not found');
      }

      const currentProfileImage = users[0].profile_image;
      if (!currentProfileImage) {
        throw new ValidationError('No profile image to delete');
      }

      await connection.execute('UPDATE users SET profile_image = NULL, updated_at = NOW() WHERE id = ?', [userId]);

      return {
        deletedImage: currentProfileImage,
        deletedAt: new Date().toISOString()
      };
    });

    res.json({
      success: true,
      message: 'Profile image deleted successfully',
      data: result
    });
  })
);

module.exports = router;