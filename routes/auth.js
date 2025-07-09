// ================================================================
// BACKEND/ROUTES/AUTH.JS - FIXED WITH PROPER NOTIFICATION SERVICE INTEGRATION
// Complete replacement with proper audit middleware and SMS service usage
// ================================================================

const express = require('express');
const { body, validationResult } = require('express-validator');

// Import enhanced middleware and services
const { 
  authenticateToken, 
  optionalAuth,
  hashPassword, 
  comparePassword,
  generateTokenPair,
  refreshAccessToken,
  incrementTokenVersion,
  generateVerificationToken,
  authRateLimiter,
  emailVerificationRateLimiter,
  passwordResetRateLimiter
} = require('../middleware/auth');

const { 
  asyncHandler, 
  ValidationError, 
  AuthenticationError,
  NotFoundError,
  DuplicateError 
} = require('../middleware/errorHandler');

// IMPORT AUDIT MIDDLEWARE
const { auditMiddleware, audit } = require('../middleware/audit');

const { executeQuery, executeTransaction } = require('../database/connection');
const notificationService = require('../services/notificationService');

const router = express.Router();

// ================================================================
// VALIDATION RULES
// ================================================================

const registerValidation = [
  body('name')
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Name must be between 2-255 characters'),
  
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required'),
  
  body('phone')
    .matches(/^\+?91[6-9]\d{9}$/)
    .withMessage('Valid Indian phone number required (+91xxxxxxxxxx format)'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be 8+ chars with uppercase, lowercase, number, and special character'),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  
  body('user_type')
    .isIn(['user', 'agent'])
    .withMessage('User type must be either "user" or "agent"'),
  
  // Agent-specific fields (conditional validation)
  body('license_number')
    .if(body('user_type').equals('agent'))
    .isLength({ min: 5, max: 100 })
    .trim()
    .matches(/^[A-Z0-9\/\-]+$/)
    .withMessage('License number required for agents (5-100 characters, alphanumeric with / and -)'),
  
  body('agency_name')
    .if(body('user_type').equals('agent'))
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Agency name required for agents (2-255 characters)'),
  
  body('experience_years')
    .if(body('user_type').equals('agent'))
    .isInt({ min: 0, max: 50 })
    .withMessage('Experience years required for agents (0-50)'),
  
  body('commission_rate')
    .if(body('user_type').equals('agent'))
    .optional()
    .isFloat({ min: 0, max: 99.99 })
    .withMessage('Commission rate must be between 0-99.99'),
  
  body('specialization')
    .if(body('user_type').equals('agent'))
    .optional()
    .isLength({ max: 1000 })
    .trim()
    .withMessage('Specialization must be under 1000 characters'),
  
  body('agent_bio')
    .if(body('user_type').equals('agent'))
    .optional()
    .isLength({ max: 2000 })
    .trim()
    .withMessage('Bio must be under 2000 characters')
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required'),
  
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password required')
];

const passwordResetValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required')
];

const passwordResetConfirmValidation = [
  body('token')
    .isLength({ min: 32 })
    .withMessage('Valid reset token required'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be 8+ chars with uppercase, lowercase, number, and special character'),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
];

// ================================================================
// REGISTRATION ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * User Registration with Role Selection
 * POST /api/auth/register
 */
router.post('/register',
  authRateLimiter,
  registerValidation,
  audit.register,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      name,
      email,
      phone,
      password,
      user_type,
      license_number,
      agency_name,
      experience_years,
      commission_rate,
      specialization,
      agent_bio
    } = req.body;

    const result = await executeTransaction(async (connection) => {
      // Check for existing email
      const [emailExists] = await connection.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );
      
      if (emailExists.length > 0) {
        throw new DuplicateError('Email address already registered');
      }

      // Check for existing phone
      const [phoneExists] = await connection.execute(
        'SELECT id FROM users WHERE phone = ?',
        [phone]
      );
      
      if (phoneExists.length > 0) {
        throw new DuplicateError('Phone number already registered');
      }

      // For agents, check license number uniqueness
      if (user_type === 'agent' && license_number) {
        const [licenseExists] = await connection.execute(
          'SELECT id FROM users WHERE license_number = ?',
          [license_number]
        );
        
        if (licenseExists.length > 0) {
          throw new DuplicateError('License number already registered');
        }
      }

      // Hash password
      const hashedPassword = await hashPassword(password);
      
      // Determine initial status based on user type
      const initialStatus = user_type === 'agent' ? 'pending_verification' : 'pending_verification';

      // Create user account
      const [userResult] = await connection.execute(`
        INSERT INTO users (
          name, email, phone, password, user_type, status,
          license_number, agency_name, experience_years, 
          commission_rate, specialization, agent_bio,
          is_buyer, is_seller
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        name, email, phone, hashedPassword, user_type, initialStatus,
        license_number || null,
        agency_name || null,
        experience_years || null,
        commission_rate || null,
        specialization || null,
        agent_bio || null,
        true,  // All users can buy properties
        true   // All users can sell properties
      ]);

      const userId = userResult.insertId;

      // If agent registration, create pending approval record
      if (user_type === 'agent') {
        await connection.execute(`
          INSERT INTO pending_approvals (
            approval_type, record_id, table_name, submitted_by, 
            submission_data, priority
          ) VALUES (?, ?, ?, ?, ?, ?)
        `, [
          'agent_application', 
          userId, 
          'users', 
          userId,
          JSON.stringify({
            agent_name: name,
            license_number: license_number,
            agency_name: agency_name,
            experience_years: experience_years
          }),
          'normal'
        ]);
      }

      // Get created user details (excluding password)
      const [newUser] = await connection.execute(`
        SELECT 
          id, uuid, name, email, phone, user_type, status, created_at,
          license_number, agency_name, experience_years, commission_rate,
          is_buyer, is_seller
        FROM users WHERE id = ?
      `, [userId]);

      const user = newUser[0];

      // FIXED: Use proper notification service functions
      let notificationResults = {
        email: { sent: false, error: null },
        sms: { sent: false, error: null }
      };

      try {
        // Use the dedicated verification email function
        const emailResult = await notificationService.sendVerificationEmail(userId);
        notificationResults.email = {
          sent: emailResult.success,
          error: emailResult.success ? null : emailResult.error
        };
      } catch (error) {
        console.error('Email verification sending failed:', error);
        notificationResults.email.error = error.message;
      }

      try {
        // Use the dedicated verification SMS function
        const smsResult = await notificationService.sendVerificationSMS(userId);
        notificationResults.sms = {
          sent: smsResult.success,
          error: smsResult.success ? null : smsResult.error
        };
      } catch (error) {
        console.error('SMS verification sending failed:', error);
        notificationResults.sms.error = error.message;
      }

      // If it's a regular user (not agent), also send welcome notification
      if (user_type === 'user') {
        try {
          await notificationService.sendWelcomeNotification({ name, email, phone });
        } catch (error) {
          console.error('Welcome notification failed:', error);
          // Don't fail registration for welcome notification failure
        }
      }

      return {
        user,
        notifications: notificationResults
      };
    });

    res.status(201).json({
      success: true,
      message: user_type === 'agent' 
        ? 'Agent registration submitted for approval. Please verify your email and phone.'
        : 'Registration successful. Please verify your email and phone.',
      data: {
        user: result.user,
        notifications: result.notifications,
        nextSteps: user_type === 'agent' 
          ? ['verify_email', 'verify_phone', 'await_approval']
          : ['verify_email', 'verify_phone']
      }
    });
  })
);

// ================================================================
// LOGIN ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * User Login
 * POST /api/auth/login
 */
router.post('/login',
  authRateLimiter,
  loginValidation,
  audit.login,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { email, password } = req.body;

    // Get user with password for verification
    const [users] = await executeQuery(`
      SELECT 
        id, uuid, name, email, phone, password, user_type, status,
        email_verified_at, phone_verified_at, 
        last_login_at, login_attempts, locked_until,
        is_buyer, is_seller, profile_image
      FROM users 
      WHERE email = ?
    `, [email]);

    if (users.length === 0) {
      throw new AuthenticationError('Invalid email or password');
    }

    const user = users[0];

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AuthenticationError(`Account locked until ${user.locked_until}`);
    }

    // Check if account is active
    if (['suspended', 'inactive'].includes(user.status)) {
      throw new AuthenticationError('Account suspended or deactivated');
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password);
    
    if (!isPasswordValid) {
      // Increment failed login attempts
      const failedAttempts = (user.login_attempts || 0) + 1;
      const lockUntil = failedAttempts >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null; // 30 min lock

      await executeQuery(`
        UPDATE users 
        SET login_attempts = ?, locked_until = ?
        WHERE id = ?
      `, [failedAttempts, lockUntil, user.id]);

      throw new AuthenticationError('Invalid email or password');
    }

    // Reset failed login attempts on successful login
    await executeQuery(`
      UPDATE users 
      SET login_attempts = 0, locked_until = NULL, last_login_at = NOW()
      WHERE id = ?
    `, [user.id]);

    // Generate JWT tokens
    const tokens = generateTokenPair(user);

    // Remove sensitive data from response
    const { password: _, ...userResponse } = user;
    userResponse.email_verified = !!user.email_verified_at;
    userResponse.phone_verified = !!user.phone_verified_at;

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        tokens
      }
    });
  })
);

/**
 * Refresh Token
 * POST /api/auth/refresh
 */
router.post('/refresh',
  authRateLimiter,
  auditMiddleware('token_refresh'),
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new ValidationError('Refresh token required');
    }

    const tokens = await refreshAccessToken(refreshToken);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: { tokens }
    });
  })
);

/**
 * Logout with Token Invalidation
 * POST /api/auth/logout
 */
router.post('/logout',
  authenticateToken,
  audit.logout,
  asyncHandler(async (req, res) => {
    // Invalidate refresh token by incrementing token version
    await incrementTokenVersion(req.user.id);
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  })
);

// ================================================================
// EMAIL VERIFICATION ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * Verify Email
 * POST /api/auth/verify-email
 */
router.post('/verify-email',
  emailVerificationRateLimiter,
  auditMiddleware('email_verification'),
  asyncHandler(async (req, res) => {
    const { token } = req.body;

    if (!token) {
      throw new ValidationError('Verification token required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, email, email_verification_token, email_verified_at
      FROM users 
      WHERE email_verification_token = ? AND email_verified_at IS NULL
    `, [token]);

    if (users.length === 0) {
      throw new ValidationError('Invalid or expired verification token');
    }

    const user = users[0];

    // Mark email as verified
    await executeQuery(`
      UPDATE users 
      SET email_verified_at = NOW(), email_verification_token = NULL, updated_at = NOW()
      WHERE id = ?
    `, [user.id]);

    res.json({
      success: true,
      message: 'Email verified successfully',
      data: {
        email: user.email,
        verified_at: new Date().toISOString()
      }
    });
  })
);

/**
 * Resend Email Verification
 * POST /api/auth/resend-email-verification
 */
router.post('/resend-email-verification',
  emailVerificationRateLimiter,
  auditMiddleware('email_verification_resend'),
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
      throw new ValidationError('Email address required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, email, email_verified_at
      FROM users 
      WHERE email = ? AND email_verified_at IS NULL
    `, [email]);

    if (users.length === 0) {
      throw new NotFoundError('User not found or email already verified');
    }

    const user = users[0];

    try {
      // FIXED: Use proper notification service function
      const result = await notificationService.sendVerificationEmail(user.id);
      
      if (result.success) {
        res.json({
          success: true,
          message: 'Verification email sent successfully',
          data: { email: result.email }
        });
      } else {
        throw new Error(result.error || 'Failed to send verification email');
      }
    } catch (error) {
      console.error('Failed to send verification email:', error);
      throw new Error('Failed to send verification email');
    }
  })
);

// ================================================================
// PHONE VERIFICATION ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * Verify Phone
 * POST /api/auth/verify-phone
 */
router.post('/verify-phone',
  emailVerificationRateLimiter,
  auditMiddleware('phone_verification'),
  asyncHandler(async (req, res) => {
    const { phone, code } = req.body;

    if (!phone || !code) {
      throw new ValidationError('Phone number and verification code required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, phone, phone_verification_code, phone_verified_at
      FROM users 
      WHERE phone = ? AND phone_verification_code = ? AND phone_verified_at IS NULL
    `, [phone, code]);

    if (users.length === 0) {
      throw new ValidationError('Invalid verification code or phone already verified');
    }

    const user = users[0];

    // Mark phone as verified
    await executeQuery(`
      UPDATE users 
      SET phone_verified_at = NOW(), phone_verification_code = NULL, updated_at = NOW()
      WHERE id = ?
    `, [user.id]);

    res.json({
      success: true,
      message: 'Phone verified successfully',
      data: {
        phone: user.phone,
        verified_at: new Date().toISOString()
      }
    });
  })
);

/**
 * Resend Phone Verification
 * POST /api/auth/resend-phone-verification
 */
router.post('/resend-phone-verification',
  emailVerificationRateLimiter,
  auditMiddleware('phone_verification_resend'),
  asyncHandler(async (req, res) => {
    const { phone } = req.body;

    if (!phone) {
      throw new ValidationError('Phone number required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, phone, phone_verified_at
      FROM users 
      WHERE phone = ? AND phone_verified_at IS NULL
    `, [phone]);

    if (users.length === 0) {
      throw new NotFoundError('User not found or phone already verified');
    }

    const user = users[0];

    try {
      // FIXED: Use proper notification service function
      const result = await notificationService.sendVerificationSMS(user.id);
      
      if (result.success) {
        res.json({
          success: true,
          message: 'Verification SMS sent successfully',
          data: { phone: result.phone }
        });
      } else {
        throw new Error(result.error || 'Failed to send verification SMS');
      }
    } catch (error) {
      console.error('Failed to send verification SMS:', error);
      throw new Error('Failed to send verification SMS');
    }
  })
);

// ================================================================
// PASSWORD RESET ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * Request Password Reset
 * POST /api/auth/forgot-password
 */
router.post('/forgot-password',
  passwordResetRateLimiter,
  passwordResetValidation,
  auditMiddleware('password_reset_request'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { email } = req.body;

    const [users] = await executeQuery(`
      SELECT id, name, email, phone FROM users WHERE email = ? AND status != 'inactive'
    `, [email]);

    // Always return success to prevent email enumeration
    if (users.length === 0) {
      return res.json({
        success: true,
        message: 'If an account with that email exists, a reset link has been sent.'
      });
    }

    const user = users[0];

    try {
      // Use the new notification service method
      const result = await notificationService.sendPasswordResetNotification(user.id);
      
      if (!result.email.sent) {
        console.error('Password reset email failed:', result.email.error);
      }
      
      if (user.phone && !result.sms.sent) {
        console.error('Password reset SMS failed:', result.sms.error);
      }
    } catch (error) {
      console.error('Password reset notification failed:', error);
      // Don't throw error to prevent revealing email existence
    }

    res.json({
      success: true,
      message: 'If an account with that email exists, a reset link has been sent.'
    });
  })
);

/**
 * Reset Password
 * POST /api/auth/reset-password
 */
router.post('/reset-password',
  passwordResetRateLimiter,
  passwordResetConfirmValidation,
  auditMiddleware('password_reset_complete'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { token, password } = req.body;

    const [users] = await executeQuery(`
      SELECT id, name, email, password_reset_token, password_reset_expires_at
      FROM users 
      WHERE password_reset_token = ? AND password_reset_expires_at > NOW()
    `, [token]);

    if (users.length === 0) {
      throw new ValidationError('Invalid or expired reset token');
    }

    const user = users[0];
    const hashedPassword = await hashPassword(password);

    await executeQuery(`
      UPDATE users 
      SET password = ?, 
          password_reset_token = NULL, 
          password_reset_expires_at = NULL,
          login_attempts = 0, 
          locked_until = NULL, 
          updated_at = NOW(),
          token_version = token_version + 1  // Invalidate all existing sessions
      WHERE id = ?
    `, [hashedPassword, user.id]);

    // Optionally send confirmation notification
    try {
      await notificationService.sendEmail({
        to: user.email,
        subject: 'Password Changed Successfully',
        html: `Your password has been successfully updated.`
      });
    } catch (error) {
      console.error('Failed to send password change confirmation:', error);
      // Not critical enough to fail the request
    }

    res.json({
      success: true,
      message: 'Password reset successfully',
      data: {
        email: user.email,
        updated_at: new Date().toISOString()
      }
    });
  })
);

// ================================================================
// ACCOUNT STATUS ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * Get Current User Status
 * GET /api/auth/me
 */
router.get('/me',
  authenticateToken,
  audit.viewProfile,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const [users] = await executeQuery(`
      SELECT 
        id, uuid, name, email, phone, user_type, status, created_at,
        email_verified_at, phone_verified_at, last_login_at,
        license_number, agency_name, experience_years, commission_rate,
        specialization, agent_bio, preferred_agent_id, profile_image,
        is_buyer, is_seller
      FROM users 
      WHERE id = ?
    `, [userId]);

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];
    user.email_verified = !!user.email_verified_at;
    user.phone_verified = !!user.phone_verified_at;

    res.json({
      success: true,
      data: { user }
    });
  })
);

/**
 * Check Email Availability
 * POST /api/auth/check-email
 */
router.post('/check-email',
  // No audit needed for availability checks
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
      throw new ValidationError('Email address required');
    }

    const [users] = await executeQuery(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    res.json({
      success: true,
      data: {
        available: users.length === 0,
        email
      }
    });
  })
);

/**
 * Check Phone Availability
 * POST /api/auth/check-phone
 */
router.post('/check-phone',
  // No audit needed for availability checks
  asyncHandler(async (req, res) => {
    const { phone } = req.body;

    if (!phone) {
      throw new ValidationError('Phone number required');
    }

    const [users] = await executeQuery(
      'SELECT id FROM users WHERE phone = ?',
      [phone]
    );

    res.json({
      success: true,
      data: {
        available: users.length === 0,
        phone
      }
    });
  })
);

// ================================================================
// USER PREFERENCES ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * Update User Buyer/Seller Preferences
 * PUT /api/auth/preferences
 */
router.put('/preferences',
  authenticateToken,
  body('preferences').isObject().withMessage('Preferences must be an object'),
  audit.updateProfile,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const { preferences } = req.body;
    
    // Build dynamic update query based on provided preferences
    const allowedFields = [
      'preferred_property_types', 'budget_min', 'budget_max', 
      'preferred_cities', 'preferred_bedrooms'
    ];
    
    const updateFields = [];
    const updateValues = [];
    
    allowedFields.forEach(field => {
      if (preferences[field] !== undefined) {
        updateFields.push(`${field} = ?`);
        updateValues.push(preferences[field]);
      }
    });
    
    if (updateFields.length === 0) {
      throw new ValidationError('No valid preferences provided');
    }
    
    updateFields.push('updated_at = NOW()');
    updateValues.push(userId);
    
    await executeQuery(`
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `, updateValues);

    res.json({
      success: true,
      message: 'Preferences updated successfully',
      data: { preferences }
    });
  })
);

/**
 * Get User Dashboard Summary
 * GET /api/auth/dashboard
 */
router.get('/dashboard',
  authenticateToken,
  audit.viewDashboard,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    // Get dashboard data using the view from schema
    const [dashboardData] = await executeQuery(`
      SELECT * FROM user_dashboard_view WHERE id = ?
    `, [userId]);

    if (dashboardData.length === 0) {
      throw new NotFoundError('User dashboard data not found');
    }

    const dashboard = dashboardData[0];

    // Get recent activity
    const [recentProperties] = await executeQuery(`
      SELECT id, title, property_type, price, status, created_at
      FROM property_listings 
      WHERE owner_id = ? 
      ORDER BY created_at DESC 
      LIMIT 5
    `, [userId]);

    const [recentFavorites] = await executeQuery(`
      SELECT pl.id, pl.title, pl.price, pl.city, uf.created_at as favorited_at
      FROM user_favorites uf
      JOIN property_listings pl ON uf.property_id = pl.id
      WHERE uf.user_id = ?
      ORDER BY uf.created_at DESC
      LIMIT 5
    `, [userId]);

    res.json({
      success: true,
      data: {
        summary: dashboard,
        recent_properties: recentProperties,
        recent_favorites: recentFavorites
      }
    });
  })
);

// ================================================================
// ADMIN ONLY ROUTES WITH AUDIT MIDDLEWARE
// ================================================================

/**
 * Check notification service health
 * GET /api/auth/notification-health
 */
router.get('/notification-health',
  authenticateToken,
  auditMiddleware('admin_system_check'),
  asyncHandler(async (req, res) => {
    // Only allow admins to check service health
    if (req.user.user_type !== 'admin') {
      throw new AuthenticationError('Admin access required');
    }

    const health = notificationService.getServiceHealth();

    res.json({
      success: true,
      data: health
    });
  })
);

/**
 * Get user's recent security events (for security-conscious users)
 * GET /api/auth/security-events
 */
router.get('/security-events',
  authenticateToken,
  auditMiddleware('view_security_events'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { days = 30 } = req.query;

    // Get user's security events from audit logs
    const [securityEvents] = await executeQuery(`
      SELECT 
        action,
        ip_address,
        user_agent,
        created_at,
        CASE 
          WHEN action LIKE '%login%' THEN 'Authentication'
          WHEN action LIKE '%password%' THEN 'Password'
          WHEN action LIKE '%verification%' THEN 'Verification'
          ELSE 'Other'
        END as event_category
      FROM audit_logs
      WHERE user_id = ?
      AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY created_at DESC
      LIMIT 50
    `, [userId, days]);

    res.json({
      success: true,
      data: {
        events: securityEvents,
        total: securityEvents.length,
        period_days: days
      }
    });
  })
);

module.exports = router;