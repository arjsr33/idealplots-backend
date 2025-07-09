// ================================================================
// MIDDLEWARE/AUDIT.JS - DPDPA 2023 COMPLIANT AUDIT MIDDLEWARE
// Automatic logging for all routes with minimal code impact
// ================================================================

const auditService = require('../services/auditService');

/**
 * Smart audit middleware that automatically logs based on route patterns
 * Usage: router.get('/profile', auditMiddleware('view_profile'), handler)
 */
const auditMiddleware = (actionType, options = {}) => {
  return async (req, res, next) => {
    const originalSend = res.send;
    const originalJson = res.json;
    
    // Capture response data
    let responseData = null;
    let responseStatus = null;
    
    // Override res.send to capture response
    res.send = function(data) {
      responseData = data;
      responseStatus = res.statusCode;
      return originalSend.call(this, data);
    };
    
    // Override res.json to capture response
    res.json = function(data) {
      responseData = data;
      responseStatus = res.statusCode;
      return originalJson.call(this, data);
    };
    
    // Continue to next middleware
    next();
    
    // Log after response is sent (non-blocking)
    res.on('finish', async () => {
      try {
        await logAuditEvent(req, res, actionType, responseData, responseStatus, options);
      } catch (error) {
        console.error('Audit logging failed:', error);
        // Don't fail the request if audit logging fails
      }
    });
  };
};

/**
 * Core audit logging logic
 */
async function logAuditEvent(req, res, actionType, responseData, responseStatus, options) {
  const userId = req.user?.id;
  const userType = req.user?.user_type;
  const isAdmin = userType === 'admin';
  const isSuccess = responseStatus >= 200 && responseStatus < 300;
  
  // Skip logging for non-security events if response was successful
  if (isSuccess && !shouldLogSuccessfulAction(actionType, userType)) {
    return;
  }
  
  const auditData = {
    userId,
    action: actionType,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    method: req.method,
    url: req.originalUrl,
    success: isSuccess,
    statusCode: responseStatus,
    ...options
  };
  
  // Route to appropriate logging method
  if (!isSuccess) {
    await logFailedAction(auditData, req, responseData);
  } else if (isAdmin && isAdminAction(actionType)) {
    await logAdminAction(auditData, req, responseData);
  } else if (isSecurityRelevantAction(actionType)) {
    await logSecurityAction(auditData, req, responseData);
  } else if (isDataAccessAction(actionType)) {
    await logDataAccess(auditData, req);
  }
}

/**
 * Log failed actions (always logged for security)
 */
async function logFailedAction(auditData, req, responseData) {
  const errorMessage = extractErrorMessage(responseData);
  
  await auditService.logSecurityEvent({
    eventType: `${auditData.action}_failed`,
    userId: auditData.userId,
    ipAddress: auditData.ipAddress,
    userAgent: auditData.userAgent,
    severity: determineSeverityFromStatus(auditData.statusCode),
    details: {
      method: auditData.method,
      url: auditData.url,
      statusCode: auditData.statusCode,
      error: errorMessage,
      requestData: sanitizeRequestData(req)
    }
  });
}

/**
 * Log admin actions
 */
async function logAdminAction(auditData, req, responseData) {
  const targetData = extractTargetFromRequest(req, responseData);
  
  await auditService.logAdminAction({
    adminId: auditData.userId,
    action: auditData.action,
    targetTable: targetData.table,
    targetRecordId: targetData.recordId,
    targetUserId: targetData.userId,
    changes: targetData.changes,
    previousData: targetData.previousData,
    reason: req.body.reason || `Admin ${auditData.action}`,
    ipAddress: auditData.ipAddress,
    userAgent: auditData.userAgent,
    severity: getActionSeverity(auditData.action)
  });
}

/**
 * Log security-relevant actions
 */
async function logSecurityAction(auditData, req, responseData) {
  await auditService.logSecurityEvent({
    eventType: auditData.action,
    userId: auditData.userId,
    ipAddress: auditData.ipAddress,
    userAgent: auditData.userAgent,
    severity: getActionSeverity(auditData.action),
    details: {
      method: auditData.method,
      url: auditData.url,
      requestData: sanitizeRequestData(req)
    }
  });
}

/**
 * Log data access events
 */
async function logDataAccess(auditData, req) {
  const accessData = extractDataAccessInfo(req, auditData.action);
  
  await auditService.logDataAccess({
    accessedBy: auditData.userId,
    dataType: accessData.dataType,
    targetUserId: accessData.targetUserId,
    fieldsAccessed: accessData.fieldsAccessed,
    purpose: accessData.purpose,
    ipAddress: auditData.ipAddress,
    userAgent: auditData.userAgent
  });
}

// ================================================================
// HELPER FUNCTIONS FOR SMART LOGGING DECISIONS
// ================================================================

/**
 * Determine if successful action should be logged
 */
function shouldLogSuccessfulAction(actionType, userType) {
  // Always log admin actions
  if (userType === 'admin') return true;
  
  // Always log security-relevant actions
  const securityActions = [
    'login', 'logout', 'password_change', 'password_reset',
    'verification', 'suspicious_activity', 'account_lock',
    'data_export', 'data_deletion', 'profile_image_upload'
  ];
  
  return securityActions.some(action => actionType.includes(action));
}

/**
 * Check if action is admin-related
 */
function isAdminAction(actionType) {
  const adminActions = [
    'admin_', 'user_delete', 'user_suspend', 'user_ban',
    'property_approve', 'property_reject', 'agent_approve',
    'agent_reject', 'system_', 'bulk_'
  ];
  
  return adminActions.some(action => actionType.includes(action));
}

/**
 * Check if action is security-relevant
 */
function isSecurityRelevantAction(actionType) {
  const securityActions = [
    'login', 'logout', 'password', 'verification', 'suspicious',
    'failed', 'unauthorized', 'security', 'fraud', 'spam',
    'bot', 'scraping', 'injection', 'breach'
  ];
  
  return securityActions.some(action => actionType.includes(action));
}

/**
 * Check if action is data access
 */
function isDataAccessAction(actionType) {
  const dataActions = [
    'view_profile', 'view_dashboard', 'view_users', 'view_properties',
    'view_enquiries', 'view_analytics', 'data_access', 'export'
  ];
  
  return dataActions.some(action => actionType.includes(action));
}

/**
 * Extract error message from response
 */
function extractErrorMessage(responseData) {
  if (typeof responseData === 'string') {
    try {
      const parsed = JSON.parse(responseData);
      return parsed.error || parsed.message || 'Unknown error';
    } catch {
      return responseData.substring(0, 200);
    }
  }
  
  if (responseData?.error) return responseData.error;
  if (responseData?.message) return responseData.message;
  
  return 'Unknown error';
}

/**
 * Determine severity from HTTP status code
 */
function determineSeverityFromStatus(statusCode) {
  if (statusCode >= 500) return 'high';
  if (statusCode === 429) return 'medium'; // Rate limiting
  if (statusCode === 401 || statusCode === 403) return 'medium';
  return 'low';
}

/**
 * Get action severity
 */
function getActionSeverity(action) {
  const highSeverity = ['delete', 'ban', 'suspend', 'forced', 'breach', 'fraud'];
  const mediumSeverity = ['login', 'password', 'admin', 'approve', 'reject'];
  
  if (highSeverity.some(keyword => action.includes(keyword))) return 'high';
  if (mediumSeverity.some(keyword => action.includes(keyword))) return 'medium';
  return 'low';
}

/**
 * Extract target information from request
 */
function extractTargetFromRequest(req, responseData) {
  const result = {
    table: 'unknown',
    recordId: null,
    userId: null,
    changes: {},
    previousData: {}
  };
  
  // Extract from URL pattern
  const urlParts = req.originalUrl.split('/');
  
  if (urlParts.includes('users')) {
    result.table = 'users';
    result.userId = req.params.id || req.params.userId;
    result.recordId = result.userId;
  } else if (urlParts.includes('properties')) {
    result.table = 'property_listings';
    result.recordId = req.params.id || req.params.propertyId;
  } else if (urlParts.includes('enquiries')) {
    result.table = 'enquiries';
    result.recordId = req.params.id || req.params.enquiryId;
  } else if (urlParts.includes('agents')) {
    result.table = 'users';
    result.userId = req.params.id || req.params.agentId;
    result.recordId = result.userId;
  }
  
  // Extract changes from request body
  if (req.body && typeof req.body === 'object') {
    result.changes = sanitizeRequestData(req);
  }
  
  return result;
}

/**
 * Extract data access information
 */
function extractDataAccessInfo(req, action) {
  const result = {
    dataType: 'unknown',
    targetUserId: req.user?.id,
    fieldsAccessed: ['basic_access'],
    purpose: 'user_request'
  };
  
  // Determine data type from URL
  if (req.originalUrl.includes('/profile')) {
    result.dataType = 'user_profile';
    result.fieldsAccessed = ['profile_data'];
    result.purpose = 'profile_view';
  } else if (req.originalUrl.includes('/dashboard')) {
    result.dataType = 'user_dashboard';
    result.fieldsAccessed = ['dashboard_summary'];
    result.purpose = 'dashboard_view';
  } else if (req.originalUrl.includes('/enquiries')) {
    result.dataType = 'user_enquiries';
    result.fieldsAccessed = ['enquiries_list'];
    result.purpose = 'enquiry_management';
  } else if (req.originalUrl.includes('/favorites')) {
    result.dataType = 'user_favorites';
    result.fieldsAccessed = ['favorites_list'];
    result.purpose = 'favorites_view';
  } else if (req.originalUrl.includes('/admin')) {
    result.dataType = 'admin_data';
    result.fieldsAccessed = ['admin_dashboard'];
    result.purpose = 'admin_management';
  }
  
  return result;
}

/**
 * Sanitize request data (remove sensitive info)
 */
function sanitizeRequestData(req) {
  const sanitized = { ...req.body };
  
  // Remove sensitive fields
  const sensitiveFields = [
    'password', 'current_password', 'new_password', 'confirm_password',
    'otp', 'verification_code', 'token', 'secret'
  ];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  
  return sanitized;
}

// ================================================================
// CONVENIENCE MIDDLEWARE FUNCTIONS
// ================================================================

/**
 * Quick middleware for common actions
 */
const audit = {
  // User actions
  login: auditMiddleware('login_attempt'),
  logout: auditMiddleware('logout'),
  register: auditMiddleware('user_registration'),
  viewProfile: auditMiddleware('view_profile'),
  updateProfile: auditMiddleware('profile_update'),
  changePassword: auditMiddleware('password_change'),
  
  // Data access
  viewDashboard: auditMiddleware('view_dashboard'),
  viewUsers: auditMiddleware('view_users'),
  viewProperties: auditMiddleware('view_properties'),
  viewEnquiries: auditMiddleware('view_enquiries'),
  
  // Property actions
  createProperty: auditMiddleware('property_create'),
  updateProperty: auditMiddleware('property_update'),
  deleteProperty: auditMiddleware('property_delete'),
  
  // Admin actions
  adminUserUpdate: auditMiddleware('admin_user_update'),
  adminUserDelete: auditMiddleware('admin_user_delete'),
  adminPropertyApprove: auditMiddleware('admin_property_approve'),
  
  // Custom action
  custom: (action, options) => auditMiddleware(action, options)
};

module.exports = {
  auditMiddleware,
  audit
};