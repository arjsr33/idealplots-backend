// ================================================================
// BACKEND/ROUTES/ENQUIRIES.JS - ENQUIRY MANAGEMENT ROUTES
// Handles enquiry submission, management, and agent assignment
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// Import middleware and services
const { 
  authenticateToken, 
  optionalAuth,
  requireAdmin,
  requireAgent,
  requireAgentOrAdmin,
  requireAgentAssignment,
  hashPassword
} = require('../middleware/auth');

const { 
  asyncHandler, 
  ValidationError, 
  NotFoundError,
  AuthorizationError 
} = require('../middleware/errorHandler');

const enquiryService = require('../services/enquiryService');

const router = express.Router();

// ================================================================
// RATE LIMITING
// ================================================================

const enquiryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 enquiries per window
  message: {
    success: false,
    error: 'Too many enquiry submissions. Please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const updateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 updates per window
  message: {
    success: false,
    error: 'Too many update requests. Please try again later.'
  }
});

// ================================================================
// VALIDATION RULES
// ================================================================

const createEnquiryValidation = [
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
    .withMessage('Valid phone number required'),
  
  body('requirements')
    .isLength({ min: 10, max: 2000 })
    .trim()
    .withMessage('Requirements must be between 10-2000 characters'),
  
  body('property_id')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Valid property ID required'),
  
  body('property_title')
    .optional()
    .isLength({ max: 255 })
    .trim()
    .withMessage('Property title must be under 255 characters'),
  
  body('property_price')
    .optional()
    .isLength({ max: 100 })
    .trim()
    .withMessage('Property price must be under 100 characters'),
  
  body('source')
    .optional()
    .isLength({ max: 100 })
    .trim()
    .withMessage('Source must be under 100 characters'),
  
  body('create_account')
    .optional()
    .isBoolean()
    .withMessage('Create account must be boolean'),
  
  body('password')
    .if(body('create_account').equals(true))
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be 8+ chars with uppercase, lowercase, number, and special character')
];

const updateEnquiryValidation = [
  body('status')
    .optional()
    .isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed'])
    .withMessage('Invalid status'),
  
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high', 'urgent'])
    .withMessage('Invalid priority'),
  
  body('assigned_to')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Valid agent ID required'),
  
  body('resolution_notes')
    .optional()
    .isLength({ max: 2000 })
    .trim()
    .withMessage('Resolution notes must be under 2000 characters'),
  
  body('customer_satisfaction_rating')
    .optional()
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1-5')
];

const addNoteValidation = [
  body('note')
    .isLength({ min: 1, max: 2000 })
    .trim()
    .withMessage('Note must be between 1-2000 characters'),
  
  body('note_type')
    .optional()
    .isIn(['internal', 'client_communication', 'system', 'follow_up_reminder'])
    .withMessage('Invalid note type'),
  
  body('communication_method')
    .optional()
    .isIn(['phone', 'email', 'whatsapp', 'in_person', 'system'])
    .withMessage('Invalid communication method'),
  
  body('next_follow_up_date')
    .optional()
    .isISO8601()
    .withMessage('Invalid follow-up date format')
];

// ================================================================
// PUBLIC ENQUIRY ROUTES
// ================================================================

/**
 * Submit new enquiry (public endpoint)
 * POST /api/enquiries
 */
router.post('/',
  enquiryLimiter,
  createEnquiryValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      name,
      email,
      phone,
      requirements,
      property_id,
      property_title,
      property_price,
      source = 'website',
      create_account = false,
      password
    } = req.body;

    // Hash password if account creation requested
    let hashedPassword = null;
    if (create_account && password) {
      hashedPassword = await hashPassword(password);
    }

    // Get additional request data
    const enquiryData = {
      name,
      email,
      phone,
      requirements,
      property_id,
      property_title,
      property_price,
      source,
      page_url: req.get('Referer'),
      user_agent: req.get('User-Agent')
    };

    const result = await enquiryService.createEnquiry(
      enquiryData,
      create_account,
      hashedPassword
    );

    res.status(201).json({
      success: true,
      message: result.account_created 
        ? 'Enquiry submitted successfully and account created. Please check your email for verification.'
        : 'Enquiry submitted successfully. We will contact you soon.',
      data: {
        enquiry: {
          id: result.enquiry.id,
          ticket_number: result.enquiry.ticket_number,
          status: result.enquiry.status,
          created_at: result.enquiry.created_at
        },
        account_created: result.account_created,
        assigned_agent: result.assigned_agent
      }
    });
  })
);

/**
 * Get enquiry by ticket number (public endpoint for status checking)
 * GET /api/enquiries/track/:ticketNumber
 */
router.get('/track/:ticketNumber',
  [param('ticketNumber').matches(/^TKT-\d{4}\d{1,2}\d{1,2}-\d+$/).withMessage('Invalid ticket number format')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { ticketNumber } = req.params;

    try {
      const enquiry = await enquiryService.getEnquiryDetails(ticketNumber, false);
      
      // Return limited public information
      res.json({
        success: true,
        data: {
          ticket_number: enquiry.ticket_number,
          status: enquiry.status,
          priority: enquiry.priority,
          created_at: enquiry.created_at,
          first_response_at: enquiry.first_response_at,
          resolved_at: enquiry.resolved_at,
          agent_name: enquiry.agent_name,
          agent_phone: enquiry.agent_phone
        }
      });
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw new NotFoundError('Ticket number not found. Please check and try again.');
      }
      throw error;
    }
  })
);

// ================================================================
// AUTHENTICATED USER ENQUIRY ROUTES
// ================================================================

/**
 * Get user's enquiries
 * GET /api/enquiries/my-enquiries
 */
router.get('/my-enquiries',
  authenticateToken,
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 }),
    query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed'])
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status;

    const filters = { user_id: userId };
    if (status) filters.status = status;

    const result = await enquiryService.getEnquiries(filters, { page, limit });

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get user's specific enquiry details
 * GET /api/enquiries/my-enquiries/:enquiryId
 */
router.get('/my-enquiries/:enquiryId',
  authenticateToken,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const userId = req.user.id;

    const enquiry = await enquiryService.getEnquiryDetails(enquiryId, true);

    // Verify user owns this enquiry
    if (enquiry.user_id !== userId) {
      throw new AuthorizationError('Access denied');
    }

    res.json({
      success: true,
      data: { enquiry }
    });
  })
);

// ================================================================
// AGENT ENQUIRY ROUTES
// ================================================================

/**
 * Get enquiries assigned to agent
 * GET /api/enquiries/agent
 */
router.get('/agent',
  authenticateToken,
  requireAgent,
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 }),
    query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
    query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
    query('search').optional().isLength({ max: 100 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const { status, priority, search } = req.query;

    const filters = { assigned_to: agentId };
    if (status) filters.status = status;
    if (priority) filters.priority = priority;
    if (search) filters.search = search;

    const result = await enquiryService.getEnquiries(filters, { page, limit });

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get specific enquiry details for agent
 * GET /api/enquiries/agent/:enquiryId
 */
router.get('/agent/:enquiryId',
  authenticateToken,
  requireAgent,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;

    const enquiry = await enquiryService.getEnquiryDetails(enquiryId, true);

    // Verify agent is assigned to this enquiry
    if (enquiry.assigned_to !== agentId) {
      throw new AuthorizationError('Access denied - enquiry not assigned to you');
    }

    res.json({
      success: true,
      data: { enquiry }
    });
  })
);

/**
 * Update enquiry (agent)
 * PUT /api/enquiries/agent/:enquiryId
 */
router.put('/agent/:enquiryId',
  updateLimiter,
  authenticateToken,
  requireAgent,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
  updateEnquiryValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;
    const updates = req.body;

    // Verify agent is assigned to this enquiry
    const enquiry = await enquiryService.getEnquiryDetails(enquiryId, false);
    if (enquiry.assigned_to !== agentId) {
      throw new AuthorizationError('Access denied - enquiry not assigned to you');
    }

    const updatedEnquiry = await enquiryService.updateEnquiry(enquiryId, updates, agentId);

    res.json({
      success: true,
      message: 'Enquiry updated successfully',
      data: { enquiry: updatedEnquiry }
    });
  })
);

/**
 * Add note to enquiry (agent)
 * POST /api/enquiries/agent/:enquiryId/notes
 */
router.post('/agent/:enquiryId/notes',
  updateLimiter,
  authenticateToken,
  requireAgent,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
  addNoteValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;
    const { note, note_type = 'internal', communication_method, next_follow_up_date } = req.body;

    // Verify agent is assigned to this enquiry
    const enquiry = await enquiryService.getEnquiryDetails(enquiryId, false);
    if (enquiry.assigned_to !== agentId) {
      throw new AuthorizationError('Access denied - enquiry not assigned to you');
    }

    const newNote = await enquiryService.addEnquiryNote(
      enquiryId,
      note,
      agentId,
      note_type,
      communication_method,
      next_follow_up_date
    );

    res.status(201).json({
      success: true,
      message: 'Note added successfully',
      data: { note: newNote }
    });
  })
);

/**
 * Get enquiry notes (agent)
 * GET /api/enquiries/agent/:enquiryId/notes
 */
router.get('/agent/:enquiryId/notes',
  authenticateToken,
  requireAgent,
  [
    param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
    query('note_type').optional().isIn(['internal', 'client_communication', 'system', 'follow_up_reminder']),
    query('limit').optional().isInt({ min: 1, max: 100 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;
    const { note_type, limit } = req.query;

    // Verify agent is assigned to this enquiry
    const enquiry = await enquiryService.getEnquiryDetails(enquiryId, false);
    if (enquiry.assigned_to !== agentId) {
      throw new AuthorizationError('Access denied - enquiry not assigned to you');
    }

    const filters = {};
    if (note_type) filters.noteType = note_type;
    if (limit) filters.limit = parseInt(limit);

    const notes = await enquiryService.getEnquiryNotes(enquiryId, filters);

    res.json({
      success: true,
      data: { notes }
    });
  })
);

// ================================================================
// ADMIN ENQUIRY ROUTES
// ================================================================

/**
 * Get all enquiries (admin)
 * GET /api/enquiries/admin
 */
router.get('/admin',
  authenticateToken,
  requireAdmin,
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
    query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
    query('assigned_to').optional().isInt({ min: 1 }),
    query('property_id').optional().isInt({ min: 1 }),
    query('search').optional().isLength({ max: 100 }),
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601(),
    query('source').optional().isLength({ max: 100 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const {
      status,
      priority,
      assigned_to,
      property_id,
      search,
      date_from,
      date_to,
      source
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

    const result = await enquiryService.getEnquiries(filters, { page, limit });

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get specific enquiry details (admin)
 * GET /api/enquiries/admin/:enquiryId
 */
router.get('/admin/:enquiryId',
  authenticateToken,
  requireAdmin,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
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
 * PUT /api/enquiries/admin/:enquiryId
 */
router.put('/admin/:enquiryId',
  updateLimiter,
  authenticateToken,
  requireAdmin,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
  updateEnquiryValidation,
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
 * POST /api/enquiries/admin/:enquiryId/assign
 */
router.post('/admin/:enquiryId/assign',
  updateLimiter,
  authenticateToken,
  requireAdmin,
  [
    param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
    body('agent_id').isInt({ min: 1 }).withMessage('Valid agent ID required'),
    body('reason').optional().isLength({ max: 500 }).trim().withMessage('Reason must be under 500 characters')
  ],
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
 * POST /api/enquiries/admin/:enquiryId/notes
 */
router.post('/admin/:enquiryId/notes',
  updateLimiter,
  authenticateToken,
  requireAdmin,
  [param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required')],
  addNoteValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const adminId = req.user.id;
    const { note, note_type = 'internal', communication_method, next_follow_up_date } = req.body;

    const newNote = await enquiryService.addEnquiryNote(
      enquiryId,
      note,
      adminId,
      note_type,
      communication_method,
      next_follow_up_date
    );

    res.status(201).json({
      success: true,
      message: 'Note added successfully',
      data: { note: newNote }
    });
  })
);

/**
 * Get enquiry analytics (admin)
 * GET /api/enquiries/admin/analytics
 */
router.get('/admin/analytics',
  authenticateToken,
  requireAdmin,
  [
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601(),
    query('agent_id').optional().isInt({ min: 1 }),
    query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed'])
  ],
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
// ENQUIRY SEARCH ROUTES
// ================================================================

/**
 * Search enquiries (admin/agent)
 * GET /api/enquiries/search
 */
router.get('/search',
  authenticateToken,
  requireAgentOrAdmin,
  [
    query('q').optional().isLength({ min: 1, max: 100 }).trim(),
    query('ticket_number').optional().matches(/^TKT-/).withMessage('Invalid ticket number format'),
    query('email').optional().isEmail(),
    query('phone').optional().isMobilePhone(),
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { q, ticket_number, email, phone, page = 1, limit = 10 } = req.query;
    const userType = req.user.user_type;
    const userId = req.user.id;

    // Build search filters
    const filters = {};
    
    if (q) filters.search = q;
    if (email) filters.email = email;
    if (phone) filters.phone = phone;
    
    // For agents, only show their assigned enquiries
    if (userType === 'agent') {
      filters.assigned_to = userId;
    }

    // Search by ticket number
    if (ticket_number) {
      try {
        const enquiry = await enquiryService.getEnquiryDetails(ticket_number, false);
        
        // Check permissions
        if (userType === 'agent' && enquiry.assigned_to !== userId) {
          throw new AuthorizationError('Access denied');
        }
        
        return res.json({
          success: true,
          data: {
            enquiries: [enquiry],
            pagination: {
              page: 1,
              limit: 1,
              total: 1,
              pages: 1,
              hasNext: false,
              hasPrev: false
            }
          }
        });
      } catch (error) {
        if (error instanceof NotFoundError) {
          return res.json({
            success: true,
            data: {
              enquiries: [],
              pagination: {
                page: 1,
                limit: 10,
                total: 0,
                pages: 0,
                hasNext: false,
                hasPrev: false
              }
            }
          });
        }
        throw error;
      }
    }

    const result = await enquiryService.getEnquiries(filters, { page: parseInt(page), limit: parseInt(limit) });

    res.json({
      success: true,
      data: result
    });
  })
);

// ================================================================
// BULK OPERATIONS (ADMIN ONLY)
// ================================================================

/**
 * Bulk update enquiries (admin)
 * POST /api/enquiries/admin/bulk-update
 */
router.post('/admin/bulk-update',
  updateLimiter,
  authenticateToken,
  requireAdmin,
  [
    body('enquiry_ids').isArray({ min: 1, max: 50 }).withMessage('Must provide 1-50 enquiry IDs'),
    body('enquiry_ids.*').isInt({ min: 1 }).withMessage('All enquiry IDs must be valid integers'),
    body('updates').isObject().withMessage('Updates object required'),
    body('updates.status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
    body('updates.priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
    body('updates.assigned_to').optional().isInt({ min: 1 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiry_ids, updates } = req.body;
    const adminId = req.user.id;

    const results = [];
    const errors_list = [];

    // Process each enquiry
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

// ================================================================
// EXPORT REPORTS (ADMIN)
// ================================================================

/**
 * Export enquiries report (admin)
 * GET /api/enquiries/admin/export
 */
router.get('/admin/export',
  authenticateToken,
  requireAdmin,
  [
    query('format').optional().isIn(['csv', 'json']).withMessage('Format must be csv or json'),
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601(),
    query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
    query('agent_id').optional().isInt({ min: 1 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { format = 'csv', date_from, date_to, status, agent_id } = req.query;

    const filters = {};
    if (date_from) filters.date_from = date_from;
    if (date_to) filters.date_to = date_to;
    if (status) filters.status = status;
    if (agent_id) filters.assigned_to = agent_id;

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

// ================================================================
// EXPORT ROUTER
// ================================================================

module.exports = router;