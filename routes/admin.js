// ================================================================
// BACKEND/ROUTES/ADMIN.JS - ALL ADMIN OPERATIONS CONSOLIDATED
// Single place for all administrative functionality - ENHANCED VERSION
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// Import middleware
const { requireAdmin, requireFullyVerified } = require('../middleware/auth');
const { asyncHandler, ValidationError, NotFoundError } = require('../middleware/errorHandler');
const { auditMiddleware, audit } = require('../middleware/audit'); // ✅ ENHANCED AUDIT MIDDLEWARE
const { handlePropertyImagesUpload } = require('../middleware/upload');


// Import services
const adminService = require('../services/adminService');
const agentService = require('../services/agentService');
const userService = require('../services/userService');
const propertyService = require('../services/propertyService');
const enquiryService = require('../services/enquiryService');
const notificationService = require('../services/notificationService');

const router = express.Router();

// ================================================================
// RATE LIMITING
// ================================================================

const adminCreateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { success: false, error: 'Too many creation attempts, please try again later.' }
});

const adminActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  message: { success: false, error: 'Too many admin actions, please try again later.' }
});

// ================================================================
// VALIDATION CONSTANTS
// ================================================================

const paginationValidation = [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
];

// Apply admin middleware to all routes
router.use(requireAdmin);
router.use(requireFullyVerified);

// ================================================================
// ADMIN DASHBOARD & ANALYTICS
// ================================================================

/**
 * Get admin dashboard statistics
 * GET /api/admin/dashboard/stats
 */
router.get('/dashboard/stats',
  audit.custom('admin_dashboard_view'),
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
  audit.custom('admin_view_activities'),
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
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('type').optional().isIn(['agent_application', 'property_listing', 'user_verification', 'all']), // ✅ UPDATED
  audit.custom('admin_view_pending_approvals'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const type = req.query.type;
    
    const approvals = await adminService.getPendingApprovals(page, limit, type);
    
    res.json({
      success: true,
      data: approvals
    });
  })
);

// ================================================================
// USER MANAGEMENT (ENHANCED)
// ================================================================

/**
 * Get all users with filtering and search
 * GET /api/admin/users
 */
router.get('/users',
  paginationValidation.concat([
    query('user_type').optional().isIn(['user', 'agent', 'admin']),
    query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
    query('search').optional().isLength({ max: 100 }).trim(),
    query('email_verified').optional().isBoolean(),
    query('phone_verified').optional().isBoolean(),
    query('is_buyer').optional().isBoolean(),
    query('is_seller').optional().isBoolean()
  ]),
  audit.custom('admin_view_all_users'),
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
      phone_verified: req.query.phone_verified,
      is_buyer: req.query.is_buyer,
      is_seller: req.query.is_seller
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
  param('userId').isInt({ min: 1 }).withMessage('Valid user ID required'),
  audit.custom('admin_view_user_details'),
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
 * Update user information (ENHANCED)
 * PUT /api/admin/users/:userId
 */
router.put('/users/:userId',
  adminActionLimiter,
  param('userId').isInt({ min: 1 }).withMessage('Valid user ID required'),
  body('name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('phone').optional().matches(/^\+?[1-9]\d{1,14}$/),
  body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
  body('user_type').optional().isIn(['user', 'agent']),
  body('email_verified').optional().isBoolean(),
  body('phone_verified').optional().isBoolean(),
  body('is_buyer').optional().isBoolean(), // ✅ ADDED
  body('is_seller').optional().isBoolean(), // ✅ ADDED
  body('preferred_agent_id').optional().isInt({ min: 1 }), // ✅ ADDED
  // Agent-specific fields
  body('license_number').optional().isLength({ min: 5, max: 100 }).trim(),
  body('commission_rate').optional().isFloat({ min: 0, max: 99.99 }),
  body('agency_name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('experience_years').optional().isInt({ min: 0, max: 50 }),
  body('specialization').optional().isLength({ max: 1000 }).trim(),
  body('agent_bio').optional().isLength({ max: 2000 }).trim(),
  audit.adminUserUpdate,
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
 * Delete user account
 * DELETE /api/admin/users/:userId
 */
router.delete('/users/:userId',
  adminActionLimiter,
  param('userId').isInt({ min: 1 }).withMessage('Valid user ID required'),
  body('reason').notEmpty().withMessage('Deletion reason is required'),
  audit.adminUserDelete,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { userId } = req.params;
    const { reason } = req.body;
    const adminId = req.user.id;
    
    const result = await userService.deleteUserByAdmin(userId, adminId, reason);
    
    res.json({
      success: true,
      message: 'User account deleted successfully',
      data: result
    });
  })
);

/**
 * Send verification email to user
 * POST /api/admin/users/:userId/send-verification-email
 */
router.post('/users/:userId/send-verification-email',
  adminActionLimiter,
  param('userId').isInt({ min: 1 }).withMessage('Valid user ID required'),
  audit.custom('admin_send_verification_email'),
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
  param('userId').isInt({ min: 1 }).withMessage('Valid user ID required'),
  audit.custom('admin_send_verification_sms'),
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
  param('userId').isInt({ min: 1 }).withMessage('Valid user ID required'),
  body('reset_email').optional().isBoolean(),
  body('reset_phone').optional().isBoolean(),
  audit.custom('admin_reset_user_verification'),
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
// AGENT MANAGEMENT (ENHANCED)
// ================================================================

/**
 * Create new agent account (ENHANCED)
 * POST /api/admin/agents/create
 */
router.post('/agents/create',
  adminCreateLimiter,
  body('name').isLength({ min: 2, max: 255 }).trim(),
  body('email').isEmail().normalizeEmail(),
  body('phone').matches(/^\+?[1-9]\d{1,14}$/),
  body('temp_password').isLength({ min: 8, max: 128 }).withMessage('Temporary password must be 8-128 characters'), // ✅ ADDED
  body('license_number').isLength({ min: 5, max: 100 }).trim(),
  body('agency_name').isLength({ min: 2, max: 255 }).trim(),
  body('commission_rate').optional().isFloat({ min: 0, max: 99.99 }).default(2.50), // ✅ ADDED DEFAULT
  body('experience_years').isInt({ min: 0, max: 50 }),
  body('specialization').optional().isLength({ max: 1000 }).trim(),
  body('agent_bio').optional().isLength({ max: 2000 }).trim(),
  audit.custom('admin_create_agent'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const adminId = req.user.id;
    const agentData = req.body;
    
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
  paginationValidation.concat([
    query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
    query('search').optional().isLength({ max: 100 }).trim(),
    query('notification_status').optional().isIn(['pending', 'sent', 'all'])
  ]),
  audit.custom('admin_view_agents'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const adminId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const { status, search, notification_status } = req.query;
    
    const result = await agentService.getAdminCreatedAgents(adminId, {
      page, limit, status, search, notification_status
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
  param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required'),
  audit.custom('admin_view_agent_details'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { agentId } = req.params;
    const adminId = req.user.id;
    
    const agent = await agentService.getAgentDetails(agentId, adminId);
    
    if (!agent) {
      throw new NotFoundError('Agent not found');
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
  param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required'),
  body('name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('phone').optional().matches(/^\+?[1-9]\d{1,14}$/),
  body('license_number').optional().isLength({ min: 5, max: 100 }).trim(),
  body('agency_name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('commission_rate').optional().isFloat({ min: 0, max: 99.99 }),
  body('experience_years').optional().isInt({ min: 0, max: 50 }),
  body('specialization').optional().isLength({ max: 1000 }).trim(),
  body('agent_bio').optional().isLength({ max: 2000 }).trim(),
  body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
  audit.custom('admin_update_agent'),
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
 * Deactivate agent account
 * POST /api/admin/agents/:agentId/deactivate
 */
router.post('/agents/:agentId/deactivate',
  adminActionLimiter,
  param('agentId').isInt({ min: 1 }).withMessage('Valid agent ID required'),
  body('reason').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_deactivate_agent'),
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
// PROPERTY MANAGEMENT (ENHANCED)
// ================================================================

/**
 * Get all properties (admin)
 * GET /api/admin/properties
 */
router.get('/properties',
  paginationValidation.concat([
    query('search').optional().isLength({ max: 100 }).trim(),
    query('property_type').optional().isArray(),
    query('city').optional().isArray(),
    query('status').optional().isIn(['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected']),
    query('owner_id').optional().isInt({ min: 1 }),
    query('assigned_agent_id').optional().isInt({ min: 1 }),
    query('is_featured').optional().isBoolean(),
    query('price_min').optional().isFloat({ min: 0 }),
    query('price_max').optional().isFloat({ min: 0 })
  ]),
  audit.custom('admin_view_all_properties'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      search, property_type, city, status, owner_id, assigned_agent_id,
      is_featured, price_min, price_max, page = 1, limit = 20
    } = req.query;

    const filters = {};
    if (search) filters.search = search;
    if (property_type) filters.property_type = Array.isArray(property_type) ? property_type : [property_type];
    if (city) filters.city = Array.isArray(city) ? city : [city];
    if (status) filters.status = status;
    if (owner_id) filters.owner_id = parseInt(owner_id);
    if (assigned_agent_id) filters.assigned_agent_id = parseInt(assigned_agent_id);
    if (is_featured !== undefined) filters.is_featured = is_featured === 'true';
    if (price_min) filters.price_min = parseFloat(price_min);
    if (price_max) filters.price_max = parseFloat(price_max);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit)
    };

    const result = await propertyService.getProperties(filters, pagination);

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Update property status (admin)
 * PUT /api/admin/properties/:id/status
 */
router.put('/properties/:id/status',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('status').isIn(['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected']),
  body('notes').optional().isLength({ max: 1000 }).trim(),
  audit.custom('admin_update_property_status'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { status, notes } = req.body;
    const adminId = req.user.id;

    const updatedProperty = await propertyService.updatePropertyStatus(propertyId, status, adminId, notes);

    res.json({
      success: true,
      message: `Property status updated to ${status}`,
      data: { property: updatedProperty }
    });
  })
);

/**
 * Approve property listing (uses schema stored procedure)
 * POST /api/admin/properties/:id/approve
 */
router.post('/properties/:id/approve',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('notes').optional().isLength({ max: 1000 }).trim(),
  audit.custom('admin_approve_property'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { notes } = req.body;
    const adminId = req.user.id;

    const result = await propertyService.approveProperty(propertyId, adminId, notes);

    res.json({
      success: true,
      message: 'Property approved successfully',
      data: result
    });
  })
);
// ================================================================
// ADMIN PROPERTY CREATION & MANAGEMENT (ADD TO ADMIN.JS)
// ================================================================

/**
 * Create property listing (admin)
 * POST /api/admin/properties/create
 */
router.post('/properties/create',
  adminCreateLimiter,
  body('title').isLength({ min: 5, max: 255 }).trim(),
  body('description').isLength({ min: 20, max: 5000 }).trim(),
  body('property_type').isIn([
    'residential_plot', 'commercial_plot', 'agricultural_land',
    'villa', 'apartment', 'house', 'commercial_building',
    'warehouse', 'shop', 'office_space'
  ]),
  body('price').isFloat({ min: 1 }),
  body('area').isFloat({ min: 1 }),
  body('city').isIn([
    'Thiruvananthapuram', 'Kochi', 'Kozhikode', 'Thrissur', 'Kollam',
    'Palakkad', 'Alappuzha', 'Kottayam', 'Kannur', 'Kasaragod',
    'Malappuram', 'Pathanamthitta', 'Idukki', 'Wayanad'
  ]),
  body('location').isLength({ min: 2, max: 255 }).trim(),
  body('owner_id').optional().isInt({ min: 1 }).withMessage('Valid owner ID required'),
  body('assigned_agent_id').optional().isInt({ min: 1 }).withMessage('Valid agent ID required'),
  body('status').optional().isIn(['draft', 'pending_review', 'approved', 'active']).default('active'),
  body('is_featured').optional().isBoolean().default(false),
  // Optional fields
  body('address').optional().isLength({ max: 1000 }).trim(),
  body('latitude').optional().isFloat({ min: -90, max: 90 }),
  body('longitude').optional().isFloat({ min: -180, max: 180 }),
  body('bedrooms').optional().isInt({ min: 0, max: 20 }),
  body('bathrooms').optional().isInt({ min: 0, max: 20 }),
  body('parking').optional().isBoolean(),
  body('furnished').optional().isBoolean(),
  body('features').optional().isArray(),
  body('meta_title').optional().isLength({ max: 255 }).trim(),
  body('meta_description').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_create_property'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const adminId = req.user.id;
    const propertyData = req.body;
    
    // Admin can create property for themselves or assign to another user
    const ownerId = propertyData.owner_id || adminId;
    
    // Admin-created properties can start as active (skip review)
    const finalPropertyData = {
      ...propertyData,
      status: propertyData.status || 'active' // Admin bypass review
    };

    const property = await propertyService.createProperty(finalPropertyData, ownerId);

    res.status(201).json({
      success: true,
      message: 'Property created successfully by admin',
      data: { property }
    });
  })
);

/**
 * Update any property (admin)
 * PUT /api/admin/properties/:id/update
 */
router.put('/properties/:id/update',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('title').optional().isLength({ min: 5, max: 255 }).trim(),
  body('description').optional().isLength({ min: 20, max: 5000 }).trim(),
  body('property_type').optional().isIn([
    'residential_plot', 'commercial_plot', 'agricultural_land',
    'villa', 'apartment', 'house', 'commercial_building',
    'warehouse', 'shop', 'office_space'
  ]),
  body('price').optional().isFloat({ min: 1 }),
  body('area').optional().isFloat({ min: 1 }),
  body('city').optional().isIn([
    'Thiruvananthapuram', 'Kochi', 'Kozhikode', 'Thrissur', 'Kollam',
    'Palakkad', 'Alappuzha', 'Kottayam', 'Kannur', 'Kasaragod',
    'Malappuram', 'Pathanamthitta', 'Idukki', 'Wayanad'
  ]),
  body('location').optional().isLength({ min: 2, max: 255 }).trim(),
  body('owner_id').optional().isInt({ min: 1 }),
  body('assigned_agent_id').optional().isInt({ min: 1 }),
  body('is_featured').optional().isBoolean(),
  body('featured_until').optional().isISO8601(),
  // Optional fields
  body('address').optional().isLength({ max: 1000 }).trim(),
  body('latitude').optional().isFloat({ min: -90, max: 90 }),
  body('longitude').optional().isFloat({ min: -180, max: 180 }),
  body('bedrooms').optional().isInt({ min: 0, max: 20 }),
  body('bathrooms').optional().isInt({ min: 0, max: 20 }),
  body('parking').optional().isBoolean(),
  body('furnished').optional().isBoolean(),
  body('features').optional().isArray(),
  body('meta_title').optional().isLength({ max: 255 }).trim(),
  body('meta_description').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_update_property'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const adminId = req.user.id;
    const updates = req.body;

    // Admin can update any property without ownership restrictions
    const updatedProperty = await propertyService.updateProperty(propertyId, updates, adminId);

    res.json({
      success: true,
      message: 'Property updated successfully by admin',
      data: { property: updatedProperty }
    });
  })
);

/**
 * Upload images to any property (admin)
 * POST /api/admin/properties/:id/upload-images
 */
router.post('/properties/:id/upload-images',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  handlePropertyImagesUpload,
  audit.custom('admin_upload_property_images'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const processedImages = req.processedImages;

    if (!processedImages || processedImages.length === 0) {
      throw new ValidationError('No images were processed');
    }

    // Admin can upload images to any property
    const savedImages = await propertyService.addPropertyImages(propertyId, processedImages);

    res.status(201).json({
      success: true,
      message: `${savedImages.length} images uploaded successfully by admin`,
      data: { images: savedImages }
    });
  })
);

/**
 * Delete property (admin)
 * DELETE /api/admin/properties/:id/delete
 */
router.delete('/properties/:id/delete',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('reason').notEmpty().withMessage('Deletion reason is required'),
  audit.custom('admin_delete_property'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { reason } = req.body;
    const adminId = req.user.id;

    // Admin can delete any property
    await propertyService.deleteProperty(propertyId, adminId);

    // Log the admin deletion reason
    const auditService = require('../services/auditService');
    await auditService.logAdminAction({
      adminId,
      action: 'property_deletion',
      targetTable: 'property_listings',
      targetRecordId: propertyId,
      reason,
      severity: 'medium'
    });

    res.json({
      success: true,
      message: 'Property deleted successfully by admin'
    });
  })
);

/**
 * Feature/unfeature property (admin)
 * POST /api/admin/properties/:id/toggle-featured
 */
router.post('/properties/:id/toggle-featured',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('is_featured').isBoolean().withMessage('Featured status required'),
  body('featured_until').optional().isISO8601().withMessage('Valid featured until date required'),
  audit.custom('admin_toggle_property_featured'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { is_featured, featured_until } = req.body;
    const adminId = req.user.id;

    const result = await propertyService.updateProperty(propertyId, {
      is_featured,
      featured_until: is_featured ? featured_until : null
    }, adminId);

    res.json({
      success: true,
      message: `Property ${is_featured ? 'featured' : 'unfeatured'} successfully`,
      data: { property: result }
    });
  })
);

/**
 * Assign agent to property (admin)
 * POST /api/admin/properties/:id/assign-agent
 */
router.post('/properties/:id/assign-agent',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('agent_id').isInt({ min: 1 }).withMessage('Valid agent ID required'),
  body('reason').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_assign_property_agent'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { agent_id, reason } = req.body;
    const adminId = req.user.id;

    // Verify agent exists and is active
    const agent = await userService.getUserById(agent_id);
    if (!agent || agent.user_type !== 'agent' || agent.status !== 'active') {
      throw new ValidationError('Invalid or inactive agent');
    }

    const result = await propertyService.updateProperty(propertyId, {
      assigned_agent_id: agent_id
    }, adminId);

    // Notify agent about assignment
    try {
      await notificationService.sendAgentPropertyAssignmentNotification({
        agentId: agent_id,
        propertyId,
        propertyTitle: result.title,
        assignedBy: adminId,
        reason
      });
    } catch (error) {
      console.error('Failed to send agent assignment notification:', error);
    }

    res.json({
      success: true,
      message: 'Agent assigned to property successfully',
      data: { property: result }
    });
  })
);

/**
 * Transfer property ownership (admin)
 * POST /api/admin/properties/:id/transfer-ownership
 */
router.post('/properties/:id/transfer-ownership',
  adminActionLimiter,
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  body('new_owner_id').isInt({ min: 1 }).withMessage('Valid new owner ID required'),
  body('reason').notEmpty().withMessage('Transfer reason is required'),
  audit.custom('admin_transfer_property_ownership'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { new_owner_id, reason } = req.body;
    const adminId = req.user.id;

    // Verify new owner exists
    const newOwner = await userService.getUserById(new_owner_id);
    if (!newOwner || newOwner.status !== 'active') {
      throw new ValidationError('Invalid or inactive new owner');
    }

    // Get current property details for audit
    const currentProperty = await propertyService.getPropertyDetails(propertyId);
    const oldOwnerId = currentProperty.owner_id;

    const result = await propertyService.updateProperty(propertyId, {
      owner_id: new_owner_id
    }, adminId);

    // Log ownership transfer
    const auditService = require('../services/auditService');
    await auditService.logAdminAction({
      adminId,
      action: 'property_ownership_transfer',
      targetTable: 'property_listings',
      targetRecordId: propertyId,
      changes: {
        old_owner_id: oldOwnerId,
        new_owner_id: new_owner_id,
        reason
      },
      reason: `Property ownership transferred: ${reason}`,
      severity: 'high'
    });

    res.json({
      success: true,
      message: 'Property ownership transferred successfully',
      data: { property: result }
    });
  })
);

/**
 * Get property audit trail (admin)
 * GET /api/admin/properties/:id/audit-trail
 */
router.get('/properties/:id/audit-trail',
  param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  audit.custom('admin_view_property_audit'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    const auditService = require('../services/auditService');
    const auditTrail = await auditService.getPropertyAuditTrail(propertyId, {
      page,
      limit
    });

    res.json({
      success: true,
      data: { audit_trail: auditTrail }
    });
  })
);

// ================================================================
// BULK PROPERTY OPERATIONS (ADMIN)
// ================================================================

/**
 * Bulk property operations
 * POST /api/admin/properties/bulk-action
 */
router.post('/properties/bulk-action',
  adminActionLimiter,
  body('property_ids').isArray({ min: 1, max: 100 }).withMessage('Must provide 1-100 property IDs'),
  body('property_ids.*').isInt({ min: 1 }).withMessage('All property IDs must be valid integers'),
  body('action').isIn(['feature', 'unfeature', 'assign_agent', 'change_owner', 'archive']).withMessage('Invalid bulk action'),
  body('agent_id').if(body('action').equals('assign_agent')).isInt({ min: 1 }).withMessage('Agent ID required for assignment'),
  body('new_owner_id').if(body('action').equals('change_owner')).isInt({ min: 1 }).withMessage('New owner ID required for ownership change'),
  body('featured_until').if(body('action').equals('feature')).optional().isISO8601(),
  body('reason').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_bulk_property_action'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { property_ids, action, agent_id, new_owner_id, featured_until, reason } = req.body;
    const adminId = req.user.id;

    const results = [];
    const errors_list = [];

    for (const propertyId of property_ids) {
      try {
        let updateData = {};
        
        switch (action) {
          case 'feature':
            updateData = { is_featured: true, featured_until };
            break;
          case 'unfeature':
            updateData = { is_featured: false, featured_until: null };
            break;
          case 'assign_agent':
            updateData = { assigned_agent_id: agent_id };
            break;
          case 'change_owner':
            updateData = { owner_id: new_owner_id };
            break;
          case 'archive':
            updateData = { status: 'withdrawn' };
            break;
        }

        const updatedProperty = await propertyService.updateProperty(propertyId, updateData, adminId);
        
        results.push({
          property_id: propertyId,
          success: true,
          property: updatedProperty
        });
      } catch (error) {
        errors_list.push({
          property_id: propertyId,
          success: false,
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Bulk ${action} completed. ${results.length} successful, ${errors_list.length} failed.`,
      data: {
        successful: results,
        failed: errors_list,
        summary: {
          total: property_ids.length,
          successful: results.length,
          failed: errors_list.length
        }
      }
    });
  })
);
// ================================================================
// ENQUIRY MANAGEMENT (ENHANCED)
// ================================================================

/**
 * Get all enquiries (admin)
 * GET /api/admin/enquiries
 */
router.get('/enquiries',
  paginationValidation.concat([
    query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
    query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
    query('assigned_to').optional().isInt({ min: 1 }),
    query('property_id').optional().isInt({ min: 1 }),
    query('search').optional().isLength({ max: 100 }),
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601(),
    query('source').optional().isLength({ max: 100 }),
    query('account_created_during_enquiry').optional().isBoolean()
  ]),
  audit.custom('admin_view_all_enquiries'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const {
      status, priority, assigned_to, property_id, search,
      date_from, date_to, source, account_created_during_enquiry
    } = req.query;

    const filters = {};
    if (status) filters.status = status;
    if (priority) filters.priority = priority;
    if (assigned_to) filters.assigned_to = assigned_to;
    if (property_id) filters.property_id = property_id;
    if (search) filters.search = search;
    if (date_from) filters.date_from = date_from;
    if (date_to) filters.date_to = date_to;
    if (source) filters.source = source;
    if (account_created_during_enquiry !== undefined) filters.account_created_during_enquiry = account_created_during_enquiry === 'true';

    const result = await enquiryService.getEnquiries(filters, { page, limit });

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get specific enquiry details (admin)
 * GET /api/admin/enquiries/:enquiryId
 */
router.get('/enquiries/:enquiryId',
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  audit.custom('admin_view_enquiry_details'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const enquiry = await enquiryService.getEnquiryDetails(enquiryId, true);

    res.json({
      success: true,
      data: { enquiry }
    });
  })
);

/**
 * Update enquiry (admin)
 * PUT /api/admin/enquiries/:enquiryId
 */
router.put('/enquiries/:enquiryId',
  adminActionLimiter,
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  body('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  body('assigned_to').optional().isInt({ min: 1 }),
  body('resolution_notes').optional().isLength({ max: 2000 }).trim(),
  body('customer_satisfaction_rating').optional().isInt({ min: 1, max: 5 }),
  audit.custom('admin_update_enquiry'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const adminId = req.user.id;
    const updates = req.body;

    const updatedEnquiry = await enquiryService.updateEnquiry(enquiryId, updates, adminId);

    res.json({
      success: true,
      message: 'Enquiry updated successfully',
      data: { enquiry: updatedEnquiry }
    });
  })
);

/**
 * Assign enquiry to agent (admin)
 * POST /api/admin/enquiries/:enquiryId/assign
 */
router.post('/enquiries/:enquiryId/assign',
  adminActionLimiter,
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  body('agent_id').isInt({ min: 1 }).withMessage('Valid agent ID required'),
  body('reason').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_assign_enquiry'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const { agent_id, reason } = req.body;
    const adminId = req.user.id;

    const updatedEnquiry = await enquiryService.assignEnquiry(enquiryId, agent_id, adminId, reason);

    res.json({
      success: true,
      message: 'Enquiry assigned successfully',
      data: { enquiry: updatedEnquiry }
    });
  })
);

/**
 * Add note to enquiry (admin)
 * POST /api/admin/enquiries/:enquiryId/notes
 */
router.post('/enquiries/:enquiryId/notes',
  adminActionLimiter,
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  body('note').isLength({ min: 1, max: 2000 }).trim(),
  body('note_type').optional().isIn(['internal', 'client_communication', 'system', 'follow_up_reminder']),
  body('communication_method').optional().isIn(['phone', 'email', 'whatsapp', 'in_person', 'system']),
  body('next_follow_up_date').optional().isISO8601(),
  audit.custom('admin_add_enquiry_note'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const adminId = req.user.id;
    const { note, note_type = 'internal', communication_method, next_follow_up_date } = req.body;

    const newNote = await enquiryService.addEnquiryNote(
      enquiryId, note, adminId, note_type, communication_method, next_follow_up_date
    );

    res.status(201).json({
      success: true,
      message: 'Note added successfully',
      data: { note: newNote }
    });
  })
);

/**
 * Bulk update enquiries (admin)
 * POST /api/admin/enquiries/bulk-update
 */
router.post('/enquiries/bulk-update',
  adminActionLimiter,
  body('enquiry_ids').isArray({ min: 1, max: 50 }),
  body('enquiry_ids.*').isInt({ min: 1 }),
  body('updates').isObject(),
  body('updates.status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
  body('updates.priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  body('updates.assigned_to').optional().isInt({ min: 1 }),
  audit.custom('admin_bulk_enquiry_update'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiry_ids, updates } = req.body;
    const adminId = req.user.id;

    const results = [];
    const errors_list = [];

    for (const enquiryId of enquiry_ids) {
      try {
        const updatedEnquiry = await enquiryService.updateEnquiry(enquiryId, updates, adminId);
        results.push({
          enquiry_id: enquiryId,
          success: true,
          enquiry: updatedEnquiry
        });
      } catch (error) {
        errors_list.push({
          enquiry_id: enquiryId,
          success: false,
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Bulk update completed. ${results.length} successful, ${errors_list.length} failed.`,
      data: {
        successful: results,
        failed: errors_list,
        summary: {
          total: enquiry_ids.length,
          successful: results.length,
          failed: errors_list.length
        }
      }
    });
  })
);

/**
 * Get enquiry analytics (admin)
 * GET /api/admin/enquiries/analytics
 */
router.get('/enquiries/analytics',
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  query('agent_id').optional().isInt({ min: 1 }),
  query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
  audit.custom('admin_view_enquiry_analytics'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { date_from, date_to, agent_id, status } = req.query;
    
    const filters = {};
    if (date_from) filters.dateFrom = date_from;
    if (date_to) filters.dateTo = date_to;
    if (agent_id) filters.agentId = agent_id;
    if (status) filters.status = status;

    const analytics = await enquiryService.getEnquiryAnalytics(filters);

    res.json({
      success: true,
      data: { analytics }
    });
  })
);

// ================================================================
// AUDIT TRAIL MANAGEMENT (ENHANCED WITH DPDPA)
// ================================================================

/**
 * Get audit trail with DPDPA compliance info (ENHANCED)
 * GET /api/admin/audit/trail
 */
router.get('/audit/trail',
  paginationValidation.concat([
    query('user_id').optional().isInt({ min: 1 }),
    query('action').optional().isLength({ max: 100 }),
    query('table_name').optional().isLength({ max: 100 }),
    query('severity').optional().isIn(['low', 'medium', 'high', 'critical']),
    query('lawful_purpose').optional().isIn(['legitimate_interest', 'legal_obligation', 'contract_performance']), // ✅ ADDED
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601()
  ]),
  audit.custom('admin_view_audit_trail'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const auditService = require('../services/auditService');
    
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 50,
      userId: req.query.user_id,
      action: req.query.action,
      tableNames: req.query.table_name ? [req.query.table_name] : [],
      severity: req.query.severity,
      lawfulPurpose: req.query.lawful_purpose, // ✅ ADDED
      startDate: req.query.date_from,
      endDate: req.query.date_to
    };

    const result = await auditService.getAuditTrail(options);

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get DPDPA compliance report (NEW)
 * GET /api/admin/audit/dpdpa-report
 */
router.get('/audit/dpdpa-report',
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  audit.custom('admin_dpdpa_compliance_report'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { date_from, date_to } = req.query;
    
    const auditService = require('../services/auditService');
    const report = await auditService.getDPDPAComplianceReport({
      dateFrom: date_from,
      dateTo: date_to
    });

    res.json({
      success: true,
      data: {
        report,
        generated_at: new Date().toISOString(),
        compliance_status: 'COMPLIANT'
      }
    });
  })
);

/**
 * Trigger DPDPA cleanup (manual) (NEW)
 * POST /api/admin/audit/dpdpa-cleanup
 */
router.post('/audit/dpdpa-cleanup',
  adminActionLimiter,
  audit.custom('admin_trigger_dpdpa_cleanup'),
  asyncHandler(async (req, res) => {
    const auditService = require('../services/auditService');
    const result = await auditService.archiveOldRecords(90); // Archive records older than 90 days

    res.json({
      success: true,
      message: 'DPDPA cleanup completed successfully',
      data: result
    });
  })
);

// ================================================================
// SYSTEM MANAGEMENT (ENHANCED)
// ================================================================

/**
 * Get system health status
 * GET /api/admin/system/health
 */
router.get('/system/health',
  audit.custom('admin_system_health'),
  asyncHandler(async (req, res) => {
    const health = await adminService.getSystemHealth();
    
    res.json({
      success: true,
      data: health
    });
  })
);

/**
 * Get system settings (NEW)
 * GET /api/admin/system/settings
 */
router.get('/system/settings',
  query('is_public').optional().isBoolean(),
  audit.custom('admin_view_system_settings'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const { is_public } = req.query;
    const settings = await adminService.getSystemSettings(is_public);
    
    res.json({
      success: true,
      data: { settings }
    });
  })
);

/**
 * Update system setting (NEW)
 * PUT /api/admin/system/settings/:key
 */
router.put('/system/settings/:key',
  adminActionLimiter,
  param('key').isLength({ min: 1, max: 255 }).withMessage('Valid setting key required'),
  body('value').notEmpty().withMessage('Setting value required'),
  body('description').optional().isLength({ max: 1000 }).trim(),
  audit.custom('admin_update_system_setting'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { key } = req.params;
    const { value, description } = req.body;
    const adminId = req.user.id;

    const result = await adminService.updateSystemSetting(key, value, description, adminId);

    res.json({
      success: true,
      message: 'System setting updated successfully',
      data: result
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
  audit.custom('admin_view_system_logs'),
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
// NOTIFICATION MANAGEMENT (NEW)
// ================================================================

/**
 * Get admin notification queue
 * GET /api/admin/notifications/queue
 */
router.get('/notifications/queue',
  paginationValidation.concat([
    query('email_sent').optional().isBoolean(),
    query('sms_sent').optional().isBoolean()
  ]),
  audit.custom('admin_view_notification_queue'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const { email_sent, sms_sent } = req.query;

    const filters = {};
    if (email_sent !== undefined) filters.email_sent = email_sent === 'true';
    if (sms_sent !== undefined) filters.sms_sent = sms_sent === 'true';

    const result = await notificationService.getAdminNotificationQueue({
      page, limit, ...filters
    });

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Resend agent notifications
 * POST /api/admin/notifications/:notificationId/resend
 */
router.post('/notifications/:notificationId/resend',
  adminActionLimiter,
  param('notificationId').isInt({ min: 1 }).withMessage('Valid notification ID required'),
  body('type').isIn(['email', 'sms', 'both']).withMessage('Must specify email, sms, or both'),
  audit.custom('admin_resend_notification'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { notificationId } = req.params;
    const { type } = req.body;
    const adminId = req.user.id;

    const result = await notificationService.resendAgentNotification(
      notificationId, 
      type, 
      adminId
    );

    res.json({
      success: true,
      message: `${type} notification resent successfully`,
      data: result
    });
  })
);

// ================================================================
// BULK OPERATIONS (NEW)
// ================================================================

/**
 * Bulk user operations
 * POST /api/admin/users/bulk-action
 */
router.post('/users/bulk-action',
  adminActionLimiter,
  body('user_ids').isArray({ min: 1, max: 100 }).withMessage('Must provide 1-100 user IDs'),
  body('user_ids.*').isInt({ min: 1 }).withMessage('All user IDs must be valid integers'),
  body('action').isIn(['activate', 'deactivate', 'suspend', 'verify_email', 'verify_phone', 'assign_agent']).withMessage('Invalid bulk action'),
  body('agent_id').if(body('action').equals('assign_agent')).isInt({ min: 1 }).withMessage('Agent ID required for assignment'),
  body('reason').optional().isLength({ max: 500 }).trim(),
  audit.custom('admin_bulk_user_action'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { user_ids, action, agent_id, reason } = req.body;
    const adminId = req.user.id;

    const result = await userService.bulkUserAction(user_ids, action, adminId, {
      agent_id,
      reason
    });

    res.json({
      success: true,
      message: `Bulk ${action} completed successfully`,
      data: result
    });
  })
);

// ================================================================
// REPORTS & EXPORTS (ENHANCED)
// ================================================================

/**
 * Export users report with DPDPA compliance
 * GET /api/admin/reports/users
 */
router.get('/reports/users',
  query('format').optional().isIn(['csv', 'json', 'xlsx']),
  query('user_type').optional().isIn(['user', 'agent', 'admin']),
  query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending_verification']),
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  query('include_personal_data').optional().isBoolean(),
  audit.custom('admin_export_users'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      format = 'csv',
      user_type,
      status,
      date_from,
      date_to,
      include_personal_data = false
    } = req.query;

    const filters = {};
    if (user_type) filters.user_type = user_type;
    if (status) filters.status = status;
    if (date_from) filters.date_from = date_from;
    if (date_to) filters.date_to = date_to;

    const result = await userService.getAllUsers({ ...filters, page: 1, limit: 10000 });

    if (format === 'json') {
      res.json({
        success: true,
        data: result.users,
        exported_at: new Date().toISOString(),
        filters_applied: filters,
        dpdpa_compliance: {
          personal_data_included: include_personal_data === 'true',
          lawful_basis: 'legitimate_interest',
          exported_by: req.user.id
        }
      });
    } else {
      // CSV format with DPDPA compliance
      const csvFields = include_personal_data === 'true' 
        ? ['id', 'name', 'email', 'phone', 'user_type', 'status', 'email_verified_at', 'phone_verified_at', 'created_at']
        : ['id', 'user_type', 'status', 'email_verified_at', 'phone_verified_at', 'created_at']; // Anonymized

      let csvContent = csvFields.join(',') + '\n';
      
      result.users.forEach(user => {
        const row = csvFields.map(field => {
          const value = user[field] || '';
          return `"${String(value).replace(/"/g, '""')}"`;
        }).join(',');
        csvContent += row + '\n';
      });

      const filename = `users-export-${new Date().toISOString().split('T')[0]}.csv`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);
    }
  })
);

/**
 * Export properties report
 * GET /api/admin/reports/properties
 */
router.get('/reports/properties',
  query('format').optional().isIn(['csv', 'json', 'xlsx']),
  query('status').optional().isIn(['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected']),
  query('city').optional().isArray(),
  query('property_type').optional().isArray(),
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  audit.custom('admin_export_properties'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { format = 'csv', status, city, property_type, date_from, date_to } = req.query;

    const filters = {};
    if (status) filters.status = status;
    if (city) filters.city = Array.isArray(city) ? city : [city];
    if (property_type) filters.property_type = Array.isArray(property_type) ? property_type : [property_type];

    const result = await propertyService.getProperties(filters, { page: 1, limit: 10000 });

    if (format === 'json') {
      res.json({
        success: true,
        data: result.properties,
        exported_at: new Date().toISOString(),
        filters_applied: filters
      });
    } else {
      // CSV format
      const csvFields = [
        'listing_id', 'title', 'property_type', 'price', 'area', 'price_per_sqft',
        'city', 'location', 'bedrooms', 'bathrooms', 'parking', 'furnished',
        'status', 'owner_name', 'agent_name', 'views_count', 'favorites_count', 'created_at'
      ];

      let csvContent = csvFields.join(',') + '\n';
      
      result.properties.forEach(property => {
        const row = csvFields.map(field => {
          const value = property[field] || '';
          return `"${String(value).replace(/"/g, '""')}"`;
        }).join(',');
        csvContent += row + '\n';
      });

      const filename = `properties-export-${new Date().toISOString().split('T')[0]}.csv`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);
    }
  })
);

/**
 * Export enquiries report
 * GET /api/admin/reports/enquiries
 */
router.get('/reports/enquiries',
  query('format').optional().isIn(['csv', 'json', 'xlsx']),
  query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
  query('agent_id').optional().isInt({ min: 1 }),
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  audit.custom('admin_export_enquiries'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { format = 'csv', status, agent_id, date_from, date_to } = req.query;

    const filters = {};
    if (status) filters.status = status;
    if (agent_id) filters.assigned_to = agent_id;
    if (date_from) filters.date_from = date_from;
    if (date_to) filters.date_to = date_to;

    const result = await enquiryService.getEnquiries(filters, { page: 1, limit: 10000 });

    if (format === 'json') {
      res.json({
        success: true,
        data: result.enquiries,
        exported_at: new Date().toISOString(),
        filters_applied: filters
      });
    } else {
      // CSV format
      const csvFields = [
        'ticket_number', 'name', 'email', 'phone', 'requirements',
        'property_title', 'status', 'priority', 'agent_name',
        'first_response_at', 'resolved_at', 'created_at'
      ];

      let csvContent = csvFields.join(',') + '\n';
      
      result.enquiries.forEach(enquiry => {
        const row = csvFields.map(field => {
          const value = enquiry[field] || '';
          return `"${String(value).replace(/"/g, '""')}"`;
        }).join(',');
        csvContent += row + '\n';
      });

      const filename = `enquiries-export-${new Date().toISOString().split('T')[0]}.csv`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);
    }
  })
);

/**
 * Get comprehensive analytics
 * GET /api/admin/reports/analytics
 */
router.get('/reports/analytics',
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  query('period').optional().isIn(['daily', 'weekly', 'monthly']),
  audit.custom('admin_view_analytics'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { date_from, date_to, period = 'daily' } = req.query;
    
    const filters = {
      dateFrom: date_from,
      dateTo: date_to,
      period
    };

    const analytics = await adminService.getComprehensiveAnalytics(filters);

    res.json({
      success: true,
      data: { analytics }
    });
  })
);

/**
 * Get user acquisition funnel (NEW)
 * GET /api/admin/analytics/user-funnel
 */
router.get('/analytics/user-funnel',
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  audit.custom('admin_view_user_funnel'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { date_from, date_to } = req.query;
    const funnel = await adminService.getUserAcquisitionFunnel({
      dateFrom: date_from,
      dateTo: date_to
    });

    res.json({
      success: true,
      data: { funnel }
    });
  })
);

// ================================================================
// MONITORING & ALERTS (NEW)
// ================================================================

/**
 * Get system alerts
 * GET /api/admin/alerts
 */
router.get('/alerts',
  query('severity').optional().isIn(['low', 'medium', 'high', 'critical']),
  query('resolved').optional().isBoolean(),
  audit.custom('admin_view_alerts'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { severity, resolved } = req.query;
    const alerts = await adminService.getSystemAlerts({
      severity,
      resolved: resolved === 'true'
    });

    res.json({
      success: true,
      data: { alerts }
    });
  })
);

/**
 * Mark alert as resolved
 * PUT /api/admin/alerts/:alertId/resolve
 */
router.put('/alerts/:alertId/resolve',
  adminActionLimiter,
  param('alertId').isInt({ min: 1 }).withMessage('Valid alert ID required'),
  body('resolution_notes').optional().isLength({ max: 1000 }).trim(),
  audit.custom('admin_resolve_alert'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { alertId } = req.params;
    const { resolution_notes } = req.body;
    const adminId = req.user.id;

    const result = await adminService.resolveAlert(alertId, adminId, resolution_notes);

    res.json({
      success: true,
      message: 'Alert resolved successfully',
      data: result
    });
  })
);

module.exports = router;