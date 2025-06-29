// ================================================================
// BACKEND/ROUTES/ADMIN.JS - ADMIN ROUTES
// Admin-only endpoints including agent creation and management
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// Import middleware
const { requireAdmin, requireFullyVerified } = require('../middleware/auth');
const { asyncHandler, ValidationError, NotFoundError } = require('../middleware/errorHandler');

// Import services
const adminService = require('../services/adminService');
const agentService = require('../services/agentService');
const userService = require('../services/userService');
const notificationService = require('../services/notificationService');

const router = express.Router();

// ================================================================
// RATE LIMITING FOR ADMIN OPERATIONS
// ================================================================

const adminCreateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Max 10 creations per 15 minutes
  message: {
    success: false,
    error: 'Too many creation attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const adminActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Max 50 admin actions per 15 minutes
  message: {
    success: false,
    error: 'Too many admin actions, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply admin middleware to all routes
router.use(requireAdmin);
router.use(requireFullyVerified);

// ================================================================
// VALIDATION RULES
// ================================================================

const agentCreationValidation = [
  body('name')
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Name must be between 2-255 characters'),
  
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required'),
  
  body('phone')
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage('Valid phone number required (E.164 format)'),
  
  body('license_number')
    .isLength({ min: 5, max: 100 })
    .trim()
    .withMessage('License number must be between 5-100 characters'),
  
  body('agency_name')
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Agency name must be between 2-255 characters'),
  
  body('commission_rate')
    .isFloat({ min: 0, max: 99.99 })
    .withMessage('Commission rate must be between 0-99.99'),
  
  body('experience_years')
    .isInt({ min: 0, max: 50 })
    .withMessage('Experience years must be between 0-50'),
  
  body('specialization')
    .optional()
    .isLength({ max: 1000 })
    .trim()
    .withMessage('Specialization must be under 1000 characters'),
  
  body('agent_bio')
    .optional()
    .isLength({ max: 2000 })
    .trim()
    .withMessage('Bio must be under 2000 characters')
];

const paginationValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1-100')
];

const userIdValidation = [
  param('userId')
    .isInt({ min: 1 })
    .withMessage('Valid user ID required')
];

// ================================================================
// AGENT MANAGEMENT ROUTES
// ================================================================

/**
 * Create new agent account
 * POST /api/admin/agents/create
 */
router.post('/agents/create',
  adminCreateLimiter,
  agentCreationValidation,
  asyncHandler(async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const adminId = req.user.id;
    const agentData = req.body;
    
    // Create agent account
    const result = await agentService.createAgentByAdmin(adminId, agentData);
    
    res.status(201).json({
      success: true,
      message: 'Agent account created successfully',
      data: result
    });
  })
);

/**
 * Get all admin-created agents
 * GET /api/admin/agents
 */
router.get('/agents',
  paginationValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const adminId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status;
    const search = req.query.search;
    
    const result = await agentService.getAdminCreatedAgents(adminId, {
      page,
      limit,
      status,
      search
    });
    
    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get specific agent details
 * GET /api/admin/agents/:agentId
 */
router.get('/agents/:agentId',
  [param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { agentId } = req.params;
    const adminId = req.user.id;
    
    const agent = await agentService.getAgentDetails(agentId, adminId);
    
    if (!agent) {
      throw new NotFoundError('Agent not found or not created by you');
    }
    
    res.json({
      success: true,
      data: agent
    });
  })
);

/**
 * Update agent information
 * PUT /api/admin/agents/:agentId
 */
router.put('/agents/:agentId',
  adminActionLimiter,
  [
    param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required'),
    body('name').optional().isLength({ min: 2, max: 255 }).trim(),
    body('phone').optional().matches(/^\+?[1-9]\d{1,14}$/),
    body('license_number').optional().isLength({ min: 5, max: 100 }).trim(),
    body('agency_name').optional().isLength({ min: 2, max: 255 }).trim(),
    body('commission_rate').optional().isFloat({ min: 0, max: 99.99 }),
    body('experience_years').optional().isInt({ min: 0, max: 50 }),
    body('specialization').optional().isLength({ max: 1000 }).trim(),
    body('agent_bio').optional().isLength({ max: 2000 }).trim(),
    body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification'])
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { agentId } = req.params;
    const adminId = req.user.id;
    const updateData = req.body;
    
    const updatedAgent = await agentService.updateAgentByAdmin(agentId, adminId, updateData);
    
    res.json({
      success: true,
      message: 'Agent updated successfully',
      data: updatedAgent
    });
  })
);

/**
 * Resend notifications to agent
 * POST /api/admin/agents/:agentId/resend-notifications
 */
router.post('/agents/:agentId/resend-notifications',
  adminActionLimiter,
  [param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { agentId } = req.params;
    const adminId = req.user.id;
    
    const result = await notificationService.resendAgentNotifications(agentId, adminId);
    
    res.json({
      success: true,
      message: 'Notifications resent successfully',
      data: result
    });
  })
);

/**
 * Get agent notification status
 * GET /api/admin/agents/:agentId/notifications
 */
router.get('/agents/:agentId/notifications',
  [param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { agentId } = req.params;
    const adminId = req.user.id;
    
    const notifications = await notificationService.getAgentNotificationStatus(agentId, adminId);
    
    res.json({
      success: true,
      data: notifications
    });
  })
);

/**
 * Deactivate agent account
 * POST /api/admin/agents/:agentId/deactivate
 */
router.post('/agents/:agentId/deactivate',
  adminActionLimiter,
  [
    param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required'),
    body('reason').optional().isLength({ max: 500 }).trim().withMessage('Reason must be under 500 characters')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { agentId } = req.params;
    const { reason } = req.body;
    const adminId = req.user.id;
    
    const result = await agentService.deactivateAgent(agentId, adminId, reason);
    
    res.json({
      success: true,
      message: 'Agent deactivated successfully',
      data: result
    });
  })
);

// ================================================================
// USER MANAGEMENT ROUTES
// ================================================================

/**
 * Get all users with filtering and search
 * GET /api/admin/users
 */
router.get('/users',
  paginationValidation.concat([
    query('user_type').optional().isIn(['user', 'agent', 'admin']),
    query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
    query('search').optional().isLength({ max: 100 }).trim()
  ]),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const filters = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 10,
      user_type: req.query.user_type,
      status: req.query.status,
      search: req.query.search,
      email_verified: req.query.email_verified,
      phone_verified: req.query.phone_verified
    };
    
    const result = await userService.getAllUsers(filters);
    
    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get specific user details
 * GET /api/admin/users/:userId
 */
router.get('/users/:userId',
  userIdValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { userId } = req.params;
    const user = await userService.getUserById(userId);
    
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    res.json({
      success: true,
      data: user
    });
  })
);

/**
 * Update user information
 * PUT /api/admin/users/:userId
 */
router.put('/users/:userId',
  adminActionLimiter,
  userIdValidation.concat([
    body('name').optional().isLength({ min: 2, max: 255 }).trim(),
    body('phone').optional().matches(/^\+?[1-9]\d{1,14}$/),
    body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
    body('user_type').optional().isIn(['user', 'agent']), // Admin can't change to admin
    body('email_verified').optional().isBoolean(),
    body('phone_verified').optional().isBoolean()
  ]),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { userId } = req.params;
    const updateData = req.body;
    const adminId = req.user.id;
    
    const updatedUser = await userService.updateUserByAdmin(userId, adminId, updateData);
    
    res.json({
      success: true,
      message: 'User updated successfully',
      data: updatedUser
    });
  })
);

/**
 * Send verification email to user
 * POST /api/admin/users/:userId/send-verification-email
 */
router.post('/users/:userId/send-verification-email',
  adminActionLimiter,
  userIdValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { userId } = req.params;
    const adminId = req.user.id;
    
    const result = await notificationService.sendVerificationEmail(userId, adminId);
    
    res.json({
      success: true,
      message: 'Verification email sent successfully',
      data: result
    });
  })
);

/**
 * Send verification SMS to user
 * POST /api/admin/users/:userId/send-verification-sms
 */
router.post('/users/:userId/send-verification-sms',
  adminActionLimiter,
  userIdValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { userId } = req.params;
    const adminId = req.user.id;
    
    const result = await notificationService.sendVerificationSMS(userId, adminId);
    
    res.json({
      success: true,
      message: 'Verification SMS sent successfully',
      data: result
    });
  })
);

/**
 * Reset user verification status
 * POST /api/admin/users/:userId/reset-verification
 */
router.post('/users/:userId/reset-verification',
  adminActionLimiter,
  userIdValidation.concat([
    body('reset_email').optional().isBoolean(),
    body('reset_phone').optional().isBoolean()
  ]),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { userId } = req.params;
    const { reset_email = true, reset_phone = true } = req.body;
    const adminId = req.user.id;
    
    const result = await userService.resetUserVerification(userId, adminId, {
      reset_email,
      reset_phone
    });
    
    res.json({
      success: true,
      message: 'User verification reset successfully',
      data: result
    });
  })
);

// ================================================================
// DASHBOARD & ANALYTICS ROUTES
// ================================================================

/**
 * Get admin dashboard statistics
 * GET /api/admin/dashboard/stats
 */
router.get('/dashboard/stats',
  asyncHandler(async (req, res) => {
    const stats = await adminService.getDashboardStats();
    
    res.json({
      success: true,
      data: stats
    });
  })
);

/**
 * Get recent admin activities
 * GET /api/admin/dashboard/activities
 */
router.get('/dashboard/activities',
  paginationValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    
    const activities = await adminService.getRecentActivities(page, limit);
    
    res.json({
      success: true,
      data: activities
    });
  })
);

/**
 * Get pending approvals
 * GET /api/admin/dashboard/pending-approvals
 */
router.get('/dashboard/pending-approvals',
  paginationValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const type = req.query.type; // 'agent', 'property', etc.
    
    const approvals = await adminService.getPendingApprovals(page, limit, type);
    
    res.json({
      success: true,
      data: approvals
    });
  })
);

// ================================================================
// SYSTEM MANAGEMENT ROUTES
// ================================================================

/**
 * Get system health status
 * GET /api/admin/system/health
 */
router.get('/system/health',
  asyncHandler(async (req, res) => {
    const health = await adminService.getSystemHealth();
    
    res.json({
      success: true,
      data: health
    });
  })
);

/**
 * Get error logs
 * GET /api/admin/system/logs
 */
router.get('/system/logs',
  paginationValidation.concat([
    query('level').optional().isIn(['error', 'warn', 'info']),
    query('from_date').optional().isISO8601(),
    query('to_date').optional().isISO8601()
  ]),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const filters = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      level: req.query.level,
      from_date: req.query.from_date,
      to_date: req.query.to_date
    };
    
    const logs = await adminService.getErrorLogs(filters);
    
    res.json({
      success: true,
      data: logs
    });
  })
);

// ================================================================
// EXPORT ROUTER
// ================================================================

module.exports = router;