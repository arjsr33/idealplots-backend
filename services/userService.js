// ================================================================
// BACKEND/SERVICES/USERSERVICE.JS - USER MANAGEMENT SERVICE
// Business logic for user management, profile operations, and admin functions
// ================================================================

const fs = require('fs').promises;
const path = require('path');
const { 
  executeQuery, 
  executeTransaction, 
  buildPaginationQuery,
  handleDatabaseError,
  logDatabaseOperation
} = require('../database/connection');

const { 
  comparePassword,
  hashPassword,
  generateVerificationToken,
  generateVerificationCode
} = require('../middleware/auth');

const {
  ValidationError,
  NotFoundError,
  DuplicateError,
  AuthenticationError
} = require('../middleware/errorHandler');

// ================================================================
// USER PROFILE FUNCTIONS
// ================================================================

/**
 * Get complete user profile by ID
 * @param {number} userId - User ID
 * @returns {Promise<Object>} User profile data
 */
const getUserProfile = async (userId) => {
  try {
    const [users] = await executeQuery(`
      SELECT 
        u.id, u.uuid, u.name, u.email, u.phone, u.user_type, u.status,
        u.email_verified_at, u.phone_verified_at, u.last_login_at, u.created_at, u.updated_at,
        u.is_buyer, u.is_seller, u.preferred_agent_id,
        u.preferred_property_types, u.budget_min, u.budget_max, 
        u.preferred_cities, u.preferred_bedrooms,
        u.profile_image, u.gender, u.address, u.city, u.state, u.pincode,
        
        -- Agent-specific fields
        u.license_number, u.commission_rate, u.agency_name, u.experience_years,
        u.specialization, u.agent_bio, u.agent_rating, u.total_sales,
        
        -- Statistics for agents
        CASE WHEN u.user_type = 'agent' THEN (
          SELECT COUNT(*) FROM user_agent_assignments 
          WHERE agent_id = u.id AND status = 'active'
        ) ELSE NULL END as active_clients,
        
        CASE WHEN u.user_type = 'agent' THEN (
          SELECT AVG(user_rating) FROM user_agent_assignments 
          WHERE agent_id = u.id AND user_rating IS NOT NULL
        ) ELSE NULL END as avg_client_rating,
        
        CASE WHEN u.user_type = 'agent' THEN (
          SELECT COUNT(*) FROM property_listings 
          WHERE assigned_agent_id = u.id AND status = 'active'
        ) ELSE NULL END as active_listings,
        
        -- User statistics
        CASE WHEN u.user_type = 'user' THEN (
          SELECT COUNT(*) FROM user_favorites WHERE user_id = u.id
        ) ELSE NULL END as total_favorites,
        
        CASE WHEN u.user_type = 'user' THEN (
          SELECT COUNT(*) FROM enquiries WHERE user_id = u.id
        ) ELSE NULL END as total_enquiries
        
      FROM users u
      WHERE u.id = ?
    `, [userId]);

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];
    
    // Parse SET fields to arrays
    if (user.preferred_property_types) {
      user.preferred_property_types = user.preferred_property_types.split(',');
    } else {
      user.preferred_property_types = [];
    }
    
    if (user.preferred_cities) {
      user.preferred_cities = user.preferred_cities.split(',');
    } else {
      user.preferred_cities = [];
    }
    
    if (user.preferred_bedrooms) {
      user.preferred_bedrooms = user.preferred_bedrooms.split(',');
    } else {
      user.preferred_bedrooms = [];
    }

    // Format verification status
    user.email_verified = !!user.email_verified_at;
    user.phone_verified = !!user.phone_verified_at;
    user.fully_verified = user.email_verified && user.phone_verified;

    // Calculate profile completion percentage
    user.profile_completion = calculateProfileCompletion(user);

    return user;

  } catch (error) {
    console.error('Error fetching user profile:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get user by ID (simpler version for admin use)
 * @param {number} userId - User ID
 * @returns {Promise<Object|null>} User data
 */
const getUserById = async (userId) => {
  try {
    const [users] = await executeQuery(`
      SELECT 
        id, uuid, name, email, phone, user_type, status, 
        email_verified_at, phone_verified_at, last_login_at, created_at,
        is_buyer, is_seller, preferred_agent_id,
        profile_image, gender, address, city, state, pincode,
        license_number, commission_rate, agency_name, experience_years,
        specialization, agent_bio, agent_rating, total_sales
      FROM users 
      WHERE id = ?
    `, [userId]);

    if (users.length === 0) {
      return null;
    }

    const user = users[0];
    
    // Format verification status
    user.email_verified = !!user.email_verified_at;
    user.phone_verified = !!user.phone_verified_at;

    return user;

  } catch (error) {
    console.error('Error fetching user by ID:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get all users with filtering (for admin)
 * @param {Object} filters - Filter options
 * @returns {Promise<Object>} Paginated user list
 */
const getAllUsers = async (filters = {}) => {
  try {
    const {
      page = 1,
      limit = 10,
      user_type,
      status,
      search,
      email_verified,
      phone_verified
    } = filters;

    let baseQuery = `
      SELECT 
        id, uuid, name, email, phone, user_type, status, 
        email_verified_at, phone_verified_at, last_login_at, created_at,
        is_buyer, is_seller, license_number, agency_name,
        CASE 
          WHEN email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL 
          THEN 'fully_verified'
          WHEN email_verified_at IS NOT NULL 
          THEN 'email_verified'
          WHEN phone_verified_at IS NOT NULL 
          THEN 'phone_verified'
          ELSE 'pending'
        END as verification_status
      FROM users 
      WHERE 1=1
    `;

    const queryParams = [];

    // Add filters
    if (user_type) {
      baseQuery += ' AND user_type = ?';
      queryParams.push(user_type);
    }

    if (status) {
      baseQuery += ' AND status = ?';
      queryParams.push(status);
    }

    if (email_verified !== undefined) {
      if (email_verified === 'true' || email_verified === true) {
        baseQuery += ' AND email_verified_at IS NOT NULL';
      } else {
        baseQuery += ' AND email_verified_at IS NULL';
      }
    }

    if (phone_verified !== undefined) {
      if (phone_verified === 'true' || phone_verified === true) {
        baseQuery += ' AND phone_verified_at IS NOT NULL';
      } else {
        baseQuery += ' AND phone_verified_at IS NULL';
      }
    }

    if (search) {
      baseQuery += ` AND (
        name LIKE ? OR 
        email LIKE ? OR 
        phone LIKE ? OR
        license_number LIKE ? OR
        agency_name LIKE ?
      )`;
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
    }

    // Build pagination query
    const { query: paginatedQuery, countQuery } = buildPaginationQuery(
      baseQuery,
      page,
      limit,
      'created_at DESC'
    );

    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;

    // Get paginated results
    const users = await executeQuery(paginatedQuery, queryParams);

    // Format verification status for each user
    users.forEach(user => {
      user.email_verified = !!user.email_verified_at;
      user.phone_verified = !!user.phone_verified_at;
    });

    return {
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    };

  } catch (error) {
    console.error('Error fetching all users:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Update user by admin
 * @param {number} userId - User ID
 * @param {number} adminId - Admin ID
 * @param {Object} updateData - Update data
 * @returns {Promise<Object>} Updated user
 */
const updateUserByAdmin = async (userId, adminId, updateData) => {
  return await executeTransaction(async (connection) => {
    try {
      // Check if user exists
      const [userCheck] = await connection.execute(
        'SELECT id, user_type FROM users WHERE id = ?',
        [userId]
      );

      if (userCheck.length === 0) {
        throw new NotFoundError('User not found');
      }

      const user = userCheck[0];

      // Define allowed fields based on user type
      const commonFields = [
        'name', 'phone', 'status', 'address', 'city', 'state', 'pincode'
      ];

      const agentFields = [
        ...commonFields,
        'license_number', 'commission_rate', 'agency_name', 'experience_years',
        'specialization', 'agent_bio'
      ];

      const allowedFields = user.user_type === 'agent' ? agentFields : commonFields;

      // Build update query
      const updateFields = [];
      const updateValues = [];

      Object.entries(updateData).forEach(([key, value]) => {
        if (allowedFields.includes(key) && value !== undefined) {
          updateFields.push(`${key} = ?`);
          updateValues.push(value);
        }
      });

      // Handle verification status updates
      if (updateData.email_verified !== undefined) {
        if (updateData.email_verified) {
          updateFields.push('email_verified_at = NOW()');
        } else {
          updateFields.push('email_verified_at = NULL');
        }
      }

      if (updateData.phone_verified !== undefined) {
        if (updateData.phone_verified) {
          updateFields.push('phone_verified_at = NOW()');
        } else {
          updateFields.push('phone_verified_at = NULL');
        }
      }

      if (updateFields.length === 0) {
        throw new ValidationError('No valid fields to update');
      }

      // Check for duplicates
      if (updateData.phone) {
        const [phoneExists] = await connection.execute(
          'SELECT id FROM users WHERE phone = ? AND id != ?',
          [updateData.phone, userId]
        );
        
        if (phoneExists.length > 0) {
          throw new DuplicateError('Phone number already in use');
        }
      }

      if (updateData.license_number && user.user_type === 'agent') {
        const [licenseExists] = await connection.execute(
          'SELECT id FROM users WHERE license_number = ? AND id != ?',
          [updateData.license_number, userId]
        );
        
        if (licenseExists.length > 0) {
          throw new DuplicateError('License number already in use');
        }
      }

      // Update user
      updateFields.push('updated_at = NOW()');
      updateValues.push(userId);

      await connection.execute(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
        updateValues
      );

      // Log the update
      await connection.execute(`
        INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, description)
        VALUES (?, 'admin_update_user', 'users', ?, ?, 'User updated by admin')
      `, [adminId, userId, JSON.stringify(updateData)]);

      logDatabaseOperation('user_updated_by_admin', {
        userId,
        adminId,
        updatedFields: Object.keys(updateData)
      });

      // Return updated user
      return await getUserById(userId);

    } catch (error) {
      console.error('Error updating user by admin:', error);
      throw handleDatabaseError(error);
    }
  });
};

/**
 * Reset user verification status
 * @param {number} userId - User ID
 * @param {number} adminId - Admin ID
 * @param {Object} options - Reset options
 * @returns {Promise<Object>} Reset result
 */
const resetUserVerification = async (userId, adminId, options = {}) => {
  return await executeTransaction(async (connection) => {
    try {
      const { reset_email = true, reset_phone = true } = options;

      // Check if user exists
      const [userCheck] = await connection.execute(
        'SELECT id, name, email, phone FROM users WHERE id = ?',
        [userId]
      );

      if (userCheck.length === 0) {
        throw new NotFoundError('User not found');
      }

      const user = userCheck[0];
      const updateFields = [];
      const updateValues = [];

      if (reset_email) {
        const emailToken = generateVerificationToken();
        updateFields.push('email_verified_at = NULL', 'email_verification_token = ?');
        updateValues.push(emailToken);
      }

      if (reset_phone) {
        const phoneCode = generateVerificationCode(6);
        updateFields.push('phone_verified_at = NULL', 'phone_verification_code = ?');
        updateValues.push(phoneCode);
      }

      if (updateFields.length === 0) {
        throw new ValidationError('No verification reset options specified');
      }

      updateFields.push('updated_at = NOW()');
      updateValues.push(userId);

      // Reset verification status
      await connection.execute(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
        updateValues
      );

      // Log the reset
      await connection.execute(`
        INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, description)
        VALUES (?, 'admin_reset_verification', 'users', ?, ?, 'Verification reset by admin')
      `, [adminId, userId, JSON.stringify(options)]);

      logDatabaseOperation('user_verification_reset', {
        userId,
        adminId,
        reset_email,
        reset_phone
      });

      return {
        userId,
        userName: user.name,
        email_reset: reset_email,
        phone_reset: reset_phone,
        resetAt: new Date().toISOString()
      };

    } catch (error) {
      console.error('Error resetting user verification:', error);
      throw handleDatabaseError(error);
    }
  });
};

// ================================================================
// PROPERTY MANAGEMENT FUNCTIONS (FOR ADMIN)
// ================================================================

/**
 * Get pending property approvals
 * @param {number} page - Page number
 * @param {number} limit - Items per page
 * @returns {Promise<Object>} Pending approvals
 */
const getPendingPropertyApprovals = async (page = 1, limit = 10) => {
  try {
    const baseQuery = `
      SELECT 
        pa.id as approval_id,
        pa.approval_type,
        pa.status as approval_status,
        pa.priority,
        pa.created_at as submitted_at,
        pl.id as property_id,
        pl.listing_id,
        pl.title,
        pl.property_type,
        pl.price,
        pl.city,
        pl.location,
        owner.id as owner_id,
        owner.name as owner_name,
        owner.email as owner_email,
        owner.phone as owner_phone
      FROM pending_approvals pa
      JOIN property_listings pl ON pa.record_id = pl.id
      JOIN users owner ON pl.owner_id = owner.id
      WHERE pa.approval_type = 'property_listing' AND pa.status = 'pending'
    `;

    // Build pagination query
    const { query: paginatedQuery, countQuery } = buildPaginationQuery(
      baseQuery,
      page,
      limit,
      'pa.created_at ASC'
    );

    // Get total count
    const [countResult] = await executeQuery(countQuery, []);
    const total = countResult[0].total;

    // Get paginated results
    const approvals = await executeQuery(paginatedQuery, []);

    return {
      approvals,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    };

  } catch (error) {
    console.error('Error fetching pending property approvals:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Approve property listing
 * @param {number} propertyId - Property ID
 * @param {number} adminId - Admin ID
 * @param {string} notes - Approval notes
 * @returns {Promise<Object>} Approval result
 */
const approvePropertyListing = async (propertyId, adminId, notes = '') => {
  return await executeTransaction(async (connection) => {
    try {
      // Use the stored procedure from your schema
      await connection.execute(
        'CALL ApprovePropertyListing(?, ?, ?)',
        [propertyId, adminId, notes]
      );

      // Get updated property details
      const [properties] = await connection.execute(`
        SELECT 
          pl.id, pl.listing_id, pl.title, pl.status, pl.approved_at,
          owner.name as owner_name, owner.email as owner_email
        FROM property_listings pl
        JOIN users owner ON pl.owner_id = owner.id
        WHERE pl.id = ?
      `, [propertyId]);

      const property = properties[0];

      logDatabaseOperation('property_approved_by_admin', {
        propertyId,
        adminId,
        notes
      });

      return {
        propertyId,
        listingId: property.listing_id,
        title: property.title,
        status: property.status,
        approvedAt: property.approved_at,
        ownerName: property.owner_name,
        ownerEmail: property.owner_email,
        notes
      };

    } catch (error) {
      console.error('Error approving property listing:', error);
      throw handleDatabaseError(error);
    }
  });
};

/**
 * Reject property listing
 * @param {number} propertyId - Property ID
 * @param {number} adminId - Admin ID
 * @param {string} reason - Rejection reason
 * @returns {Promise<Object>} Rejection result
 */
const rejectPropertyListing = async (propertyId, adminId, reason) => {
  return await executeTransaction(async (connection) => {
    try {
      // Update property status to rejected
      await connection.execute(`
        UPDATE property_listings 
        SET status = 'rejected', 
            reviewed_by = ?, 
            reviewed_at = NOW(),
            rejection_reason = ?,
            updated_at = NOW()
        WHERE id = ?
      `, [adminId, reason, propertyId]);

      // Update pending approval record
      await connection.execute(`
        UPDATE pending_approvals 
        SET status = 'rejected',
            approved_by = ?,
            approved_at = NOW(),
            rejection_reason = ?
        WHERE approval_type = 'property_listing' 
          AND record_id = ? 
          AND status = 'pending'
      `, [adminId, reason, propertyId]);

      // Log the rejection
      await connection.execute(`
        INSERT INTO audit_logs (
          user_id, action, table_name, record_id, description
        ) VALUES (?, 'reject', 'property_listings', ?, ?)
      `, [adminId, propertyId, `Property listing rejected: ${reason}`]);

      // Get property details
      const [properties] = await connection.execute(`
        SELECT 
          pl.id, pl.listing_id, pl.title, pl.status,
          owner.name as owner_name, owner.email as owner_email
        FROM property_listings pl
        JOIN users owner ON pl.owner_id = owner.id
        WHERE pl.id = ?
      `, [propertyId]);

      const property = properties[0];

      logDatabaseOperation('property_rejected_by_admin', {
        propertyId,
        adminId,
        reason
      });

      return {
        propertyId,
        listingId: property.listing_id,
        title: property.title,
        status: property.status,
        ownerName: property.owner_name,
        ownerEmail: property.owner_email,
        reason,
        rejectedAt: new Date().toISOString()
      };

    } catch (error) {
      console.error('Error rejecting property listing:', error);
      throw handleDatabaseError(error);
    }
  });
};

// ================================================================
// ADMIN DASHBOARD FUNCTIONS
// ================================================================

/**
 * Get admin dashboard statistics
 * @returns {Promise<Object>} Dashboard stats
 */
const getAdminDashboardStats = async () => {
  try {
    const [stats] = await executeQuery(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE user_type = 'user') as total_users,
        (SELECT COUNT(*) FROM users WHERE user_type = 'agent') as total_agents,
        (SELECT COUNT(*) FROM users WHERE user_type = 'user' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_users_this_month,
        (SELECT COUNT(*) FROM users WHERE user_type = 'agent' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_agents_this_month,
        
        (SELECT COUNT(*) FROM property_listings WHERE status = 'active') as active_properties,
        (SELECT COUNT(*) FROM property_listings WHERE status = 'pending_review') as pending_properties,
        (SELECT COUNT(*) FROM property_listings WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_properties_this_month,
        
        (SELECT COUNT(*) FROM enquiries WHERE status IN ('new', 'assigned', 'in_progress')) as pending_enquiries,
        (SELECT COUNT(*) FROM enquiries WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_enquiries_this_month,
        
        (SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending') as total_pending_approvals,
        (SELECT COUNT(*) FROM pending_approvals WHERE approval_type = 'property_listing' AND status = 'pending') as pending_property_approvals,
        (SELECT COUNT(*) FROM pending_approvals WHERE approval_type = 'agent_application' AND status = 'pending') as pending_agent_approvals,
        
        (SELECT COUNT(*) FROM users WHERE email_verified_at IS NULL) as unverified_emails,
        (SELECT COUNT(*) FROM users WHERE phone_verified_at IS NULL) as unverified_phones
    `);

    return stats[0];

  } catch (error) {
    console.error('Error fetching admin dashboard stats:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get recent admin activities
 * @param {number} page - Page number
 * @param {number} limit - Items per page
 * @returns {Promise<Object>} Recent activities
 */
const getRecentAdminActivities = async (page = 1, limit = 20) => {
  try {
    const baseQuery = `
      SELECT 
        al.id,
        al.action,
        al.table_name,
        al.record_id,
        al.description,
        al.severity,
        al.created_at,
        admin.name as admin_name,
        admin.email as admin_email
      FROM audit_logs al
      JOIN users admin ON al.user_id = admin.id
      WHERE admin.user_type = 'admin'
    `;

    // Build pagination query
    const { query: paginatedQuery, countQuery } = buildPaginationQuery(
      baseQuery,
      page,
      limit,
      'al.created_at DESC'
    );

    // Get total count
    const [countResult] = await executeQuery(countQuery, []);
    const total = countResult[0].total;

    // Get paginated results
    const activities = await executeQuery(paginatedQuery, []);

    return {
      activities,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    };

  } catch (error) {
    console.error('Error fetching recent admin activities:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get pending approvals
 * @param {number} page - Page number
 * @param {number} limit - Items per page
 * @param {string} type - Approval type filter
 * @returns {Promise<Object>} Pending approvals
 */
const getPendingApprovals = async (page = 1, limit = 10, type = null) => {
  try {
    let baseQuery = `
      SELECT 
        pa.id,
        pa.approval_type,
        pa.record_id,
        pa.table_name,
        pa.status,
        pa.priority,
        pa.created_at,
        pa.submission_data,
        submitter.name as submitted_by_name,
        submitter.email as submitted_by_email
      FROM pending_approvals pa
      JOIN users submitter ON pa.submitted_by = submitter.id
      WHERE pa.status IN ('pending', 'under_review')
    `;

    const queryParams = [];

    if (type) {
      baseQuery += ' AND pa.approval_type = ?';
      queryParams.push(type);
    }

    // Build pagination query
    const { query: paginatedQuery, countQuery } = buildPaginationQuery(
      baseQuery,
      page,
      limit,
      'pa.priority DESC, pa.created_at ASC'
    );

    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;

    // Get paginated results
    const approvals = await executeQuery(paginatedQuery, queryParams);

    // Parse submission_data JSON for each approval
    approvals.forEach(approval => {
      if (approval.submission_data) {
        try {
          approval.submission_data = JSON.parse(approval.submission_data);
        } catch (e) {
          approval.submission_data = {};
        }
      }
    });

    return {
      approvals,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    };

  } catch (error) {
    console.error('Error fetching pending approvals:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// HELPER FUNCTIONS
// ================================================================

/**
 * Calculate profile completion percentage based on filled fields
 * @param {Object} user - User object
 * @returns {number} Completion percentage
 */
function calculateProfileCompletion(user) {
  const requiredFields = ['name', 'email', 'phone'];
  const optionalFields = ['gender', 'address', 'city', 'profile_image'];
  const userTypeFields = user.user_type === 'agent' 
    ? ['license_number', 'agency_name', 'experience_years', 'agent_bio']
    : ['preferred_property_types', 'budget_min', 'budget_max', 'preferred_cities'];

  const allFields = [...requiredFields, ...optionalFields, ...userTypeFields];
  const filledFields = allFields.filter(field => {
    const value = user[field];
    if (Array.isArray(value)) return value.length > 0;
    return value !== null && value !== undefined && value !== '';
  });

  return Math.round((filledFields.length / allFields.length) * 100);
}

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core user functions
  getUserProfile,
  getUserById,
  getAllUsers,
  updateUserByAdmin,
  resetUserVerification,
  
  // Property management
  getPendingPropertyApprovals,
  approvePropertyListing,
  rejectPropertyListing,
  
  // Dashboard functions
  getAdminDashboardStats,
  getRecentAdminActivities,
  getPendingApprovals,
  
  // Helper functions
  calculateProfileCompletion
};