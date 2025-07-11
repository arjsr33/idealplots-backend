// ================================================================
// BACKEND/SERVICES/ADMINSERVICE.JS - ADMIN SERVICE
// Administrative functions, system monitoring, and management operations
// ================================================================

const { 
  executeQuery, 
  executeTransaction,
  getPoolStatus,
  handleDatabaseError,
  logDatabaseOperation
} = require('../database/connection');

const {
  ValidationError,
  NotFoundError
} = require('../middleware/errorHandler');

// ================================================================
// DASHBOARD STATISTICS
// ================================================================

/**
 * Get comprehensive dashboard statistics
 * @returns {Promise<Object>} Dashboard statistics
 */
const getDashboardStats = async () => {
  try {
    // Execute all queries in parallel
    const [
      userStats,
      propertyStats,
      enquiryStats,
      approvalStats,
      agentStats,
      favoriteStats,
      adminAgentStats
    ] = await Promise.all([
      // User statistics
      executeQuery(`
        SELECT 
          SUM(user_type = 'user') as total_users,
          SUM(user_type = 'agent') as total_agents,
          SUM(user_type = 'admin') as total_admins,
          SUM(status = 'active') as active_users,
          SUM(status = 'pending_verification') as pending_verification_users,
          SUM(user_type = 'user' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_users_this_month,
          SUM(user_type = 'agent' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_agents_this_month,
          SUM(email_verified_at IS NOT NULL) as email_verified_users,
          SUM(phone_verified_at IS NOT NULL) as phone_verified_users,
          SUM(email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL) as fully_verified_users
        FROM users
      `),
      
      // Property statistics
      executeQuery(`
        SELECT 
          COUNT(*) as total_properties,
          SUM(status = 'active') as active_properties,
          SUM(status = 'pending_review') as pending_properties,
          SUM(status = 'sold') as sold_properties,
          SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_properties_this_month
        FROM property_listings
      `),
      
      // Enquiry statistics
      executeQuery(`
        SELECT 
          COUNT(*) as total_enquiries,
          SUM(status IN ('new', 'assigned', 'in_progress')) as pending_enquiries,
          SUM(status = 'resolved') as resolved_enquiries,
          SUM(created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as new_enquiries_this_month
        FROM enquiries
      `),
      
      // Approval statistics
      executeQuery(`
        SELECT 
          SUM(status = 'pending') as total_pending_approvals,
          SUM(approval_type = 'property_listing' AND status = 'pending') as pending_property_approvals,
          SUM(approval_type = 'agent_application' AND status = 'pending') as pending_agent_approvals,
          SUM(approval_type = 'user_verification' AND status = 'pending') as pending_user_verifications
        FROM pending_approvals
      `),
      
      // Agent performance
      executeQuery(`
        SELECT 
          SUM(status = 'active') as active_agent_assignments,
          AVG(user_rating) as avg_agent_rating
        FROM user_agent_assignments
        WHERE user_rating IS NOT NULL
      `),
      
      // Favorites and views
      executeQuery(`
        SELECT 
          COUNT(*) as total_favorites,
          (SELECT COUNT(*) FROM property_views WHERE viewed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as property_views_this_month
        FROM user_favorites
      `),
      
      // Admin created agents
      executeQuery(`
        SELECT 
          COUNT(*) as admin_created_agents,
          SUM(email_sent = FALSE OR sms_sent = FALSE) as pending_agent_notifications
        FROM admin_created_notifications
      `)
    ]);

    // Combine all results
    const statistics = {
      ...userStats[0],
      ...propertyStats[0],
      ...enquiryStats[0],
      ...approvalStats[0],
      ...agentStats[0],
      ...favoriteStats[0],
      ...adminAgentStats[0]
    };

    // Calculate derived statistics
    const userVerificationRate = statistics.total_users > 0 
      ? ((statistics.fully_verified_users / statistics.total_users) * 100).toFixed(1)
      : 0;

    const propertyApprovalRate = statistics.total_properties > 0
      ? ((statistics.active_properties / statistics.total_properties) * 100).toFixed(1)
      : 0;

    const enquiryResolutionRate = statistics.total_enquiries > 0
      ? ((statistics.resolved_enquiries / statistics.total_enquiries) * 100).toFixed(1)
      : 0;

    return {
      ...statistics,
      user_verification_rate: parseFloat(userVerificationRate),
      property_approval_rate: parseFloat(propertyApprovalRate),
      enquiry_resolution_rate: parseFloat(enquiryResolutionRate),
      avg_agent_rating: statistics.avg_agent_rating ? parseFloat(statistics.avg_agent_rating).toFixed(2) : null
    };

  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    throw new DatabaseError('Failed to fetch dashboard statistics', { 
      originalError: error,
      query: 'dashboard_stats'
    });
  }
};

// ================================================================
// RECENT ACTIVITIES
// ================================================================

/**
 * Get recent admin activities with filtering
 * @param {number} page - Page number
 * @param {number} limit - Items per page
 * @param {Object} filters - Activity filters
 * @returns {Promise<Object>} Recent activities
 */
const getRecentActivities = async (page = 1, limit = 20, filters = {}) => {
  try {
    const { 
      action_type,
      severity,
      date_from,
      date_to,
      admin_id
    } = filters;

    let baseQuery = `
      SELECT 
        al.id,
        al.action,
        al.table_name,
        al.record_id,
        al.description,
        al.severity,
        al.created_at,
        al.ip_address,
        admin.id as admin_id,
        admin.name as admin_name,
        admin.email as admin_email,
        
        -- Additional context based on table_name
        CASE 
          WHEN al.table_name = 'users' AND al.action LIKE '%agent%' THEN (
            SELECT CONCAT(u.name, ' (', u.email, ')') 
            FROM users u WHERE u.id = al.record_id
          )
          WHEN al.table_name = 'property_listings' THEN (
            SELECT CONCAT(pl.title, ' - ', pl.city) 
            FROM property_listings pl WHERE pl.id = al.record_id
          )
          ELSE NULL
        END as record_details
        
      FROM audit_logs al
      LEFT JOIN users admin ON al.user_id = admin.id
      WHERE 1=1
    `;

    const queryParams = [];

    // Add filters
    if (action_type) {
      baseQuery += ' AND al.action LIKE ?';
      queryParams.push(`%${action_type}%`);
    }

    if (severity) {
      baseQuery += ' AND al.severity = ?';
      queryParams.push(severity);
    }

    if (date_from) {
      baseQuery += ' AND al.created_at >= ?';
      queryParams.push(date_from);
    }

    if (date_to) {
      baseQuery += ' AND al.created_at <= ?';
      queryParams.push(date_to);
    }

    if (admin_id) {
      baseQuery += ' AND al.user_id = ?';
      queryParams.push(admin_id);
    }

    // Build pagination
    const offset = (page - 1) * limit;
    const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
    
    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;

    // Get paginated results
    baseQuery += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);
    
    const activities = await executeQuery(baseQuery, queryParams);

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
    console.error('Error fetching recent activities:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// PENDING APPROVALS MANAGEMENT
// ================================================================

/**
 * Get pending approvals with detailed information
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
        pa.admin_notes,
        
        submitter.id as submitter_id,
        submitter.name as submitted_by_name,
        submitter.email as submitted_by_email,
        submitter.user_type as submitter_type,
        
        reviewer.name as assigned_reviewer_name,
        
        -- Type-specific details
        CASE 
          WHEN pa.approval_type = 'property_listing' THEN (
            SELECT JSON_OBJECT(
              'title', pl.title,
              'property_type', pl.property_type,
              'price', pl.price,
              'city', pl.city,
              'location', pl.location,
              'status', pl.status
            )
            FROM property_listings pl WHERE pl.id = pa.record_id
          )
          WHEN pa.approval_type = 'agent_application' THEN (
            SELECT JSON_OBJECT(
              'name', u.name,
              'email', u.email,
              'license_number', u.license_number,
              'agency_name', u.agency_name,
              'experience_years', u.experience_years
            )
            FROM users u WHERE u.id = pa.record_id
          )
          WHEN pa.approval_type = 'user_verification' THEN (
            SELECT JSON_OBJECT(
              'name', u.name,
              'email', u.email,
              'user_type', u.user_type,
              'email_verified', u.email_verified_at IS NOT NULL,
              'phone_verified', u.phone_verified_at IS NOT NULL
            )
            FROM users u WHERE u.id = pa.record_id
          )
          ELSE NULL
        END as type_details
        
      FROM pending_approvals pa
      JOIN users submitter ON pa.submitted_by = submitter.id
      LEFT JOIN users reviewer ON pa.assigned_reviewer = reviewer.id
      WHERE pa.status IN ('pending', 'under_review')
    `;

    const queryParams = [];

    if (type) {
      baseQuery += ' AND pa.approval_type = ?';
      queryParams.push(type);
    }

    // Build pagination
    const offset = (page - 1) * limit;
    const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
    
    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;

    // Get paginated results
    baseQuery += ' ORDER BY pa.priority DESC, pa.created_at ASC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);
    
    const approvals = await executeQuery(baseQuery, queryParams);

    // Parse JSON fields
    approvals.forEach(approval => {
      if (approval.submission_data) {
        try {
          approval.submission_data = JSON.parse(approval.submission_data);
        } catch (e) {
          approval.submission_data = {};
        }
      }
      
      if (approval.type_details) {
        try {
          approval.type_details = JSON.parse(approval.type_details);
        } catch (e) {
          approval.type_details = {};
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
// SYSTEM HEALTH MONITORING
// ================================================================

/**
 * Get comprehensive system health status
 * @returns {Promise<Object>} System health information
 */
const getSystemHealth = async () => {
  try {
    // Database health
    const dbStatus = getPoolStatus();
    
    // Query performance check
    const startTime = Date.now();
    await executeQuery('SELECT 1 as health_check');
    const queryTime = Date.now() - startTime;
    
    // Get database table sizes and statistics
    const [tableStats] = await executeQuery(`
      SELECT 
        table_name,
        table_rows,
        ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
      FROM information_schema.tables 
      WHERE table_schema = DATABASE()
      ORDER BY (data_length + index_length) DESC
      LIMIT 10
    `);

    // Get recent error counts
    const [errorStats] = await executeQuery(`
      SELECT 
        COUNT(*) as total_errors,
        COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as errors_24h,
        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_errors,
        COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_errors
      FROM audit_logs 
      WHERE severity IN ('high', 'critical')
        AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    `);

    // System load indicators
    const [systemLoad] = await executeQuery(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE last_login_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) as active_users_1h,
        (SELECT COUNT(*) FROM property_views WHERE viewed_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) as page_views_1h,
        (SELECT COUNT(*) FROM enquiries WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) as new_enquiries_1h,
        (SELECT AVG(TIMESTAMPDIFF(SECOND, created_at, first_response_at)) FROM enquiries WHERE first_response_at IS NOT NULL AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as avg_response_time_24h
    `);

    // Determine overall health status
    let healthStatus = 'healthy';
    const issues = [];

    if (queryTime > 1000) {
      healthStatus = 'warning';
      issues.push('Database response time is slow');
    }

    if (errorStats[0].errors_24h > 10) {
      healthStatus = 'warning';
      issues.push('High error rate in last 24 hours');
    }

    if (errorStats[0].critical_errors > 0) {
      healthStatus = 'critical';
      issues.push('Critical errors detected');
    }

    if (dbStatus.freeConnections < 2) {
      healthStatus = 'warning';
      issues.push('Low database connection availability');
    }

    return {
      status: healthStatus,
      timestamp: new Date().toISOString(),
      issues,
      database: {
        status: dbStatus,
        query_time_ms: queryTime,
        table_stats: tableStats
      },
      errors: errorStats[0],
      system_load: systemLoad[0],
      uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      node_version: process.version
    };

  } catch (error) {
    console.error('Error checking system health:', error);
    return {
      status: 'error',
      timestamp: new Date().toISOString(),
      error: error.message
    };
  }
};

// ================================================================
// ERROR LOG MANAGEMENT
// ================================================================

/**
 * Get error logs with filtering
 * @param {Object} filters - Log filters
 * @returns {Promise<Object>} Error logs
 */
const getErrorLogs = async (filters = {}) => {
  try {
    const {
      page = 1,
      limit = 20,
      level = null,
      from_date = null,
      to_date = null,
      action = null
    } = filters;

    let baseQuery = `
      SELECT 
        al.id,
        al.action,
        al.table_name,
        al.record_id,
        al.description,
        al.severity,
        al.created_at,
        al.ip_address,
        al.user_agent,
        admin.name as admin_name,
        admin.email as admin_email
      FROM audit_logs al
      LEFT JOIN users admin ON al.user_id = admin.id
      WHERE al.severity IN ('medium', 'high', 'critical')
    `;

    const queryParams = [];

    // Add filters
    if (level) {
      baseQuery += ' AND al.severity = ?';
      queryParams.push(level);
    }

    if (from_date) {
      baseQuery += ' AND al.created_at >= ?';
      queryParams.push(from_date);
    }

    if (to_date) {
      baseQuery += ' AND al.created_at <= ?';
      queryParams.push(to_date);
    }

    if (action) {
      baseQuery += ' AND al.action LIKE ?';
      queryParams.push(`%${action}%`);
    }

    // Build pagination
    const offset = (page - 1) * limit;
    const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
    
    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;

    // Get paginated results
    baseQuery += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);
    
    const logs = await executeQuery(baseQuery, queryParams);

    return {
      logs,
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
    console.error('Error fetching error logs:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// USER ANALYTICS
// ================================================================

/**
 * Get user analytics and insights
 * @param {string} period - Time period ('7d', '30d', '90d', '1y')
 * @returns {Promise<Object>} User analytics
 */
const getUserAnalytics = async (period = '30d') => {
  try {
    let dateFilter;
    switch (period) {
      case '7d':
        dateFilter = 'DATE_SUB(NOW(), INTERVAL 7 DAY)';
        break;
      case '90d':
        dateFilter = 'DATE_SUB(NOW(), INTERVAL 90 DAY)';
        break;
      case '1y':
        dateFilter = 'DATE_SUB(NOW(), INTERVAL 1 YEAR)';
        break;
      default:
        dateFilter = 'DATE_SUB(NOW(), INTERVAL 30 DAY)';
    }

    const [analytics] = await executeQuery(`
      SELECT 
        -- Registration Analytics
        COUNT(CASE WHEN created_at >= ${dateFilter} THEN 1 END) as new_registrations,
        COUNT(CASE WHEN created_at >= ${dateFilter} AND user_type = 'user' THEN 1 END) as new_users,
        COUNT(CASE WHEN created_at >= ${dateFilter} AND user_type = 'agent' THEN 1 END) as new_agents,
        
        -- Verification Analytics
        COUNT(CASE WHEN email_verified_at >= ${dateFilter} THEN 1 END) as email_verifications,
        COUNT(CASE WHEN phone_verified_at >= ${dateFilter} THEN 1 END) as phone_verifications,
        
        -- Engagement Analytics
        COUNT(CASE WHEN last_login_at >= ${dateFilter} THEN 1 END) as active_users,
        COUNT(CASE WHEN last_login_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as weekly_active_users,
        
        -- Geographic Distribution
        COUNT(CASE WHEN city = 'Kochi' THEN 1 END) as users_kochi,
        COUNT(CASE WHEN city = 'Thiruvananthapuram' THEN 1 END) as users_tvm,
        COUNT(CASE WHEN city = 'Kozhikode' THEN 1 END) as users_kozhikode,
        COUNT(CASE WHEN city = 'Thrissur' THEN 1 END) as users_thrissur,
        COUNT(CASE WHEN city NOT IN ('Kochi', 'Thiruvananthapuram', 'Kozhikode', 'Thrissur') AND city IS NOT NULL THEN 1 END) as users_other_cities,
        
        -- User Type Distribution
        AVG(CASE WHEN user_type = 'agent' THEN commission_rate END) as avg_agent_commission,
        AVG(CASE WHEN user_type = 'agent' THEN experience_years END) as avg_agent_experience
        
      FROM users
      WHERE status != 'deleted'
    `);

    // Get daily registration trends
    const [dailyTrends] = await executeQuery(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as registrations,
        COUNT(CASE WHEN user_type = 'user' THEN 1 END) as user_registrations,
        COUNT(CASE WHEN user_type = 'agent' THEN 1 END) as agent_registrations
      FROM users 
      WHERE created_at >= ${dateFilter}
      GROUP BY DATE(created_at)
      ORDER BY date DESC
      LIMIT 30
    `);

    return {
      period,
      analytics: analytics[0],
      daily_trends: dailyTrends
    };

  } catch (error) {
    console.error('Error fetching user analytics:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// SYSTEM SETTINGS MANAGEMENT
// ================================================================

/**
 * Get system settings
 * @param {boolean} publicOnly - Return only public settings
 * @returns {Promise<Array>} System settings
 */
const getSystemSettings = async (publicOnly = false) => {
  try {
    let query = `
      SELECT setting_key, setting_value, setting_type, description, is_public
      FROM system_settings
    `;

    const params = [];

    if (publicOnly) {
      query += ' WHERE is_public = TRUE';
    }

    query += ' ORDER BY setting_key';

    const settings = await executeQuery(query, params);

    // Parse values based on type
    settings.forEach(setting => {
      if (setting.setting_type === 'boolean') {
        setting.setting_value = setting.setting_value === 'true';
      } else if (setting.setting_type === 'number') {
        setting.setting_value = parseFloat(setting.setting_value);
      } else if (setting.setting_type === 'json') {
        try {
          setting.setting_value = JSON.parse(setting.setting_value);
        } catch (e) {
          setting.setting_value = null;
        }
      }
    });

    return settings;

  } catch (error) {
    console.error('Error fetching system settings:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Update system setting
 * @param {string} key - Setting key
 * @param {any} value - Setting value
 * @param {number} adminId - Admin ID
 * @returns {Promise<Object>} Update result
 */
const updateSystemSetting = async (key, value, adminId) => {
  return await executeTransaction(async (connection) => {
    try {
      // Convert value to string based on type
      let stringValue;
      if (typeof value === 'boolean') {
        stringValue = value.toString();
      } else if (typeof value === 'object') {
        stringValue = JSON.stringify(value);
      } else {
        stringValue = value.toString();
      }

      // Update or insert setting
      await connection.execute(`
        INSERT INTO system_settings (setting_key, setting_value, updated_at)
        VALUES (?, ?, NOW())
        ON DUPLICATE KEY UPDATE
        setting_value = VALUES(setting_value),
        updated_at = NOW()
      `, [key, stringValue]);

      // Log the change
      await connection.execute(`
        INSERT INTO audit_logs (user_id, action, table_name, record_id, description)
        VALUES (?, 'update_setting', 'system_settings', NULL, ?)
      `, [adminId, `Updated system setting: ${key} = ${stringValue}`]);

      logDatabaseOperation('system_setting_updated', {
        key,
        value: stringValue,
        adminId
      });

      return {
        key,
        value,
        updatedAt: new Date().toISOString()
      };

    } catch (error) {
      console.error('Error updating system setting:', error);
      throw handleDatabaseError(error);
    }
  });
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Dashboard
  getDashboardStats,
  getRecentActivities,
  
  // Approvals
  getPendingApprovals,
  
  // System monitoring
  getSystemHealth,
  getErrorLogs,
  
  // Analytics
  getUserAnalytics,
  
  // Settings
  getSystemSettings,
  updateSystemSetting
};