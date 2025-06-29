/**
 * Get Client Details
 * GET /api/agents/clients/:clientId
 */
router.get('/clients/:clientId',
  [param('clientId').isInt({ min: 1 }).withMessage('Valid client ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const agentId = req.user.id;
    const { clientId } = req.params;

    const [clients] = await executeQuery(`
      SELECT 
        uaa.id as assignment_id,
        uaa.assignment_type,
        uaa.assignment_reason,
        uaa.status as assignment_status,
        uaa.properties_shown,
        uaa.meetings_conducted,
        uaa.user_rating,
        uaa.agent_notes,
        uaa.assigned_at,
        uaa.last_contact_at,
        
        u.id as client_id,
        u.uuid as client_uuid,
        u.name as client_name,
        u.email as client_email,
        u.phone as client_phone,
        u.preferred_property_types,
        u.budget_min,
        u.budget_max,
        u.preferred_cities,
        u.preferred_bedrooms,
        u.address,
        u.city,
        u.state,
        u.pincode,
        u.created_at as client_joined_at,
        
        -- Client activity stats
        (SELECT COUNT(*) FROM enquiries WHERE user_id = u.id) as total_enquiries,
        (SELECT COUNT(*) FROM user_favorites WHERE user_id = u.id) as total_favorites,
        (SELECT COUNT(*) FROM property_views WHERE user_id = u.id) as total_property_views
        
      FROM user_agent_assignments uaa
      JOIN users u ON uaa.user_id = u.id
      WHERE uaa.agent_id = ? AND u.id = ? AND uaa.status = 'active'
    `, [agentId, clientId]);

    if (clients.length === 0) {
      throw new NotFoundError('Client not found or not assigned to you');
    }

    const client = clients[0];

    // Parse SET fields
    if (client.preferred_property_types) {
      client.preferred_property_types = client.preferred_property_types.split(',');
    }
    if (client.preferred_cities) {
      client.preferred_cities = client.preferred_cities.split(',');
    }
    if (client.preferred_bedrooms) {
      client.preferred_bedrooms = client.preferred_bedrooms.split(',');
    }

    // Get recent enquiries from this client
    const [recentEnquiries] = await executeQuery(`
      SELECT 
        id, ticket_number, requirements, property_title, status, created_at
      FROM enquiries 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 5
    `, [clientId]);

    client.recent_enquiries = recentEnquiries;

    res.json({
      success: true,
      data: client
    });
  })
);

/**
 * Update Client Assignment Notes
 * PUT /api/agents/clients/:clientId/notes
 */
router.put('/clients/:clientId/notes',
  agentActionLimiter,
  [
    param('clientId').isInt({ min: 1 }).withMessage('Valid client ID required'),
    body('notes').isLength({ max: 1000 }).trim().withMessage('Notes must be under 1000 characters'),
    body('properties_shown').optional().isInt({ min: 0 }),
    body('meetings_conducted').optional().isInt({ min: 0 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }
    
    const agentId = req.user.id;
    const { clientId } = req.params;
    const { notes, properties_shown, meetings_conducted } = req.body;

    const result = await executeTransaction(async (connection) => {
      // Verify assignment exists
      const [assignmentCheck] = await connection.execute(
        'SELECT id FROM user_agent_assignments WHERE agent_id = ? AND user_id = ? AND status = "active"',
        [agentId, clientId]
      );

      if (assignmentCheck.length === 0) {
        throw new NotFoundError('Client assignment not found');
      }

      // ================================================================
// BACKEND/ROUTES/AGENTS.JS - AGENT DASHBOARD ROUTES
// Routes for agent-specific functionality
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// Import middleware
const { authenticateToken, requireAgent, requireFullyVerified } = require('../middleware/auth');
const { asyncHandler, ValidationError, NotFoundError } = require('../middleware/errorHandler');

// Import database functions
const { executeQuery, executeTransaction, handleDatabaseError } = require('../database/connection');

const router = express.Router();

// ================================================================
// RATE LIMITING FOR AGENT OPERATIONS
// ================================================================

const agentActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 agent actions per 15 minutes
  message: {
    success: false,
    error: 'Too many requests, please try again later.'
  }
});

// Apply agent middleware to all routes
router.use(authenticateToken);
router.use(requireAgent);

// ================================================================
// AGENT DASHBOARD ROUTES
// ================================================================

/**
 * Get Agent Dashboard Overview
 * GET /api/agents/dashboard
 */
router.get('/dashboard',
  asyncHandler(async (req, res) => {
    const agentId = req.user.id;
    
    const [dashboardData] = await executeQuery(`
      SELECT 
        u.name, u.email, u.phone, u.agency_name, u.license_number,
        u.agent_rating, u.total_sales, u.commission_rate,
        
        -- Active clients count
        (SELECT COUNT(*) FROM user_agent_assignments WHERE agent_id = ? AND status = 'active') as active_clients,
        
        -- Total enquiries assigned
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = ?) as total_enquiries,
        
        -- Resolved enquiries
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = ? AND status = 'resolved') as resolved_enquiries,
        
        -- Properties assigned to agent
        (SELECT COUNT(*) FROM property_listings WHERE assigned_agent_id = ?) as assigned_properties,
        
        -- Active property listings
        (SELECT COUNT(*) FROM property_listings WHERE assigned_agent_id = ? AND status = 'active') as active_properties,
        
        -- This month's new clients
        (SELECT COUNT(*) FROM user_agent_assignments 
         WHERE agent_id = ? AND assigned_at >= DATE_SUB(NOW(), INTERVAL 1 MONTH)) as new_clients_this_month,
        
        -- Pending enquiries
        (SELECT COUNT(*) FROM enquiries 
         WHERE assigned_to = ? AND status IN ('new', 'assigned', 'in_progress')) as pending_enquiries,
        
        -- Average client rating
        (SELECT AVG(user_rating) FROM user_agent_assignments 
         WHERE agent_id = ? AND user_rating IS NOT NULL) as avg_client_rating
         
      FROM users u WHERE u.id = ?
    `, [agentId, agentId, agentId, agentId, agentId, agentId, agentId, agentId, agentId]);

    const dashboard = dashboardData[0];
    
    // Calculate performance metrics
    const enquiryResolutionRate = dashboard.total_enquiries > 0 
      ? ((dashboard.resolved_enquiries / dashboard.total_enquiries) * 100).toFixed(1)
      : 0;

    res.json({
      success: true,
      data: {
        ...dashboard,
        enquiry_resolution_rate: parseFloat(enquiryResolutionRate),
        avg_client_rating: dashboard.avg_client_rating ? parseFloat(dashboard.avg_client_rating).toFixed(1) : null
      }
    });
  })
);

// ================================================================
// CLIENT MANAGEMENT ROUTES
// ================================================================

/**
 * Get Agent's Assigned Clients
 * GET /api/agents/clients
 */
router.get('/clients',
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 }),
    query('status').optional().isIn(['active', 'inactive', 'completed']),
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
    const status = req.query.status || 'active';
    const search = req.query.search;
    const offset = (page - 1) * limit;

    let baseQuery = `
      SELECT 
        uaa.id as assignment_id,
        uaa.assignment_type,
        uaa.assignment_reason,
        uaa.status as assignment_status,
        uaa.properties_shown,
        uaa.meetings_conducted,
        uaa.user_rating,
        uaa.agent_notes,
        uaa.assigned_at,
        uaa.last_contact_at,
        u.id as client_id,
        u.uuid as client_uuid,
        u.name as client_name,
        u.email as client_email,
        u.phone as client_phone,
        u.preferred_property_types,
        u.budget_min,
        u.budget_max,
        u.preferred_cities,
        u.preferred_bedrooms,
        
        -- Recent enquiry count
        (SELECT COUNT(*) FROM enquiries e WHERE e.user_id = u.id 
         AND e.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as recent_enquiries
         
      FROM user_agent_assignments uaa
      JOIN users u ON uaa.user_id = u.id
      WHERE uaa.agent_id = ?
    `;
    
    const queryParams = [agentId];

    if (status) {
      baseQuery += ' AND uaa.status = ?';
      queryParams.push(status);
    }

    if (search) {
      baseQuery += ' AND (u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ?)';
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm);
    }

    // Get total count
    const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
    const [[{ total }]] = await executeQuery(countQuery, queryParams);

    // Get paginated results
    baseQuery += ' ORDER BY uaa.assigned_at DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);
    
    const clients = await executeQuery(baseQuery, queryParams);

    // Parse SET fields for each client
    clients.forEach(client => {
      if (client.preferred_property_types) {
        client.preferred_property_types = client.preferred_property_types.split(',');
      }
      if (client.preferred_cities) {
        client.preferred_cities = client.preferred_cities.split(',');
      }
      if (client.preferred_bedrooms) {
        client.preferred_bedrooms = client.preferred_bedrooms.split(',');
      }
    });

    res.json({
      success: true,
      data: {
        clients,
        pagination: {
          page,
          limit,
          total: parseInt(total),
          pages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1
        }
      }
    });
  })
);

/**
 * Get Client Details
 * GET /api/agents/clients/:clientId
 */
router.get('/clients/:clientId',
  [param('clientId').isInt({ min: 1 }).with