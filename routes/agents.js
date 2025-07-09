// ================================================================
// BACKEND/ROUTES/AGENTS.JS - AGENT OPERATIONS ONLY
// Clean separation: Only agent-specific functionality
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// Import middleware
const { authenticateToken, requireAgent, requireFullyVerified } = require('../middleware/auth');
const { asyncHandler, ValidationError, NotFoundError } = require('../middleware/errorHandler');
const { audit } = require('../middleware/audit'); // ✅ AUDIT MIDDLEWARE

// Import database functions
const { executeQuery, executeTransaction } = require('../database/connection');

const router = express.Router();

// ================================================================
// RATE LIMITING FOR AGENT OPERATIONS
// ================================================================

const agentActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
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
  audit.custom('agent_dashboard_view'),
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
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('status').optional().isIn(['active', 'inactive', 'completed']),
  query('search').optional().isLength({ max: 100 }),
  audit.custom('agent_view_clients'),
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
  param('clientId').isInt({ min: 1 }).withMessage('Valid client ID required'),
  audit.custom('agent_view_client_details'),
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
  param('clientId').isInt({ min: 1 }).withMessage('Valid client ID required'),
  body('notes').isLength({ max: 1000 }).trim().withMessage('Notes must be under 1000 characters'),
  body('properties_shown').optional().isInt({ min: 0 }),
  body('meetings_conducted').optional().isInt({ min: 0 }),
  audit.custom('agent_update_client_notes'),
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

      // Update assignment notes
      const updateFields = ['agent_notes = ?', 'last_contact_at = NOW()', 'updated_at = NOW()'];
      const updateValues = [notes];

      if (properties_shown !== undefined) {
        updateFields.push('properties_shown = ?');
        updateValues.push(properties_shown);
      }

      if (meetings_conducted !== undefined) {
        updateFields.push('meetings_conducted = ?');
        updateValues.push(meetings_conducted);
      }

      updateValues.push(agentId, clientId);

      await connection.execute(
        `UPDATE user_agent_assignments SET ${updateFields.join(', ')} WHERE agent_id = ? AND user_id = ?`,
        updateValues
      );

      return {
        clientId,
        notes,
        properties_shown,
        meetings_conducted,
        updatedAt: new Date().toISOString()
      };
    });

    res.json({
      success: true,
      message: 'Client notes updated successfully',
      data: result
    });
  })
);

// ================================================================
// AGENT ENQUIRY MANAGEMENT
// ================================================================

/**
 * Get enquiries assigned to agent
 * GET /api/agents/enquiries
 */
router.get('/enquiries',
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('status').optional().isIn(['new', 'assigned', 'in_progress', 'resolved', 'closed']),
  query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  query('search').optional().isLength({ max: 100 }),
  audit.custom('agent_view_enquiries'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const { status, priority, search } = req.query;
    const offset = (page - 1) * limit;

    let baseQuery = `
      SELECT 
        e.id,
        e.ticket_number,
        e.name,
        e.email,
        e.phone,
        e.requirements,
        e.property_title,
        e.status,
        e.priority,
        e.created_at,
        e.first_response_at,
        e.resolved_at,
        u.name as client_name,
        u.preferred_property_types,
        u.budget_min,
        u.budget_max
      FROM enquiries e
      LEFT JOIN users u ON e.user_id = u.id
      WHERE e.assigned_to = ?
    `;

    const queryParams = [agentId];

    if (status) {
      baseQuery += ' AND e.status = ?';
      queryParams.push(status);
    }

    if (priority) {
      baseQuery += ' AND e.priority = ?';
      queryParams.push(priority);
    }

    if (search) {
      baseQuery += ' AND (e.name LIKE ? OR e.email LIKE ? OR e.phone LIKE ? OR e.ticket_number LIKE ?)';
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    // Get total count
    const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
    const [[{ total }]] = await executeQuery(countQuery, queryParams);

    // Get paginated results
    baseQuery += ' ORDER BY e.created_at DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);

    const enquiries = await executeQuery(baseQuery, queryParams);

    res.json({
      success: true,
      data: {
        enquiries,
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
 * Get specific enquiry details for agent
 * GET /api/agents/enquiries/:enquiryId
 */
router.get('/enquiries/:enquiryId',
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  audit.custom('agent_view_enquiry_details'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;

    const [enquiries] = await executeQuery(`
      SELECT 
        e.*,
        u.name as client_name,
        u.email as client_email,
        u.phone as client_phone,
        u.preferred_property_types,
        u.budget_min,
        u.budget_max,
        u.preferred_cities,
        pl.title as property_title,
        pl.listing_id,
        pl.property_type,
        pl.price,
        pl.city as property_city,
        pl.location as property_location
      FROM enquiries e
      LEFT JOIN users u ON e.user_id = u.id
      LEFT JOIN property_listings pl ON e.property_id = pl.id
      WHERE e.id = ? AND e.assigned_to = ?
    `, [enquiryId, agentId]);

    if (enquiries.length === 0) {
      throw new NotFoundError('Enquiry not found or not assigned to you');
    }

    const enquiry = enquiries[0];

    // Get enquiry notes/responses
    const [notes] = await executeQuery(`
      SELECT 
        en.id,
        en.note,
        en.note_type,
        en.communication_method,
        en.next_follow_up_date,
        en.created_at,
        u.name as created_by_name,
        u.user_type as created_by_type
      FROM enquiry_notes en
      JOIN users u ON en.user_id = u.id
      WHERE en.enquiry_id = ?
      ORDER BY en.created_at DESC
    `, [enquiryId]);

    res.json({
      success: true,
      data: {
        enquiry,
        notes
      }
    });
  })
);

/**
 * Update enquiry (agent)
 * PUT /api/agents/enquiries/:enquiryId
 */
router.put('/enquiries/:enquiryId',
  agentActionLimiter,
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  body('status').optional().isIn(['assigned', 'in_progress', 'resolved']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  body('resolution_notes').optional().isLength({ max: 2000 }).trim(),
  body('customer_satisfaction_rating').optional().isInt({ min: 1, max: 5 }),
  audit.custom('agent_update_enquiry'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;
    const updates = req.body;

    const result = await executeTransaction(async (connection) => {
      // Verify agent is assigned to this enquiry
      const [enquiryCheck] = await connection.execute(
        'SELECT id, status FROM enquiries WHERE id = ? AND assigned_to = ?',
        [enquiryId, agentId]
      );

      if (enquiryCheck.length === 0) {
        throw new NotFoundError('Enquiry not found or not assigned to you');
      }

      // Build update query
      const updateFields = [];
      const updateValues = [];

      if (updates.status) {
        updateFields.push('status = ?');
        updateValues.push(updates.status);
        
        // Set resolved_at if status is resolved
        if (updates.status === 'resolved') {
          updateFields.push('resolved_at = NOW()');
        }
      }

      if (updates.priority) {
        updateFields.push('priority = ?');
        updateValues.push(updates.priority);
      }

      if (updates.resolution_notes) {
        updateFields.push('resolution_notes = ?');
        updateValues.push(updates.resolution_notes);
      }

      if (updates.customer_satisfaction_rating) {
        updateFields.push('customer_satisfaction_rating = ?');
        updateValues.push(updates.customer_satisfaction_rating);
      }

      if (updateFields.length === 0) {
        throw new ValidationError('No valid fields to update');
      }

      updateFields.push('updated_at = NOW()');
      updateValues.push(enquiryId);

      await connection.execute(
        `UPDATE enquiries SET ${updateFields.join(', ')} WHERE id = ?`,
        updateValues
      );

      // Get updated enquiry
      const [updatedEnquiry] = await connection.execute(
        'SELECT * FROM enquiries WHERE id = ?',
        [enquiryId]
      );

      return updatedEnquiry[0];
    });

    res.json({
      success: true,
      message: 'Enquiry updated successfully',
      data: { enquiry: result }
    });
  })
);

/**
 * Add note to enquiry (agent)
 * POST /api/agents/enquiries/:enquiryId/notes
 */
router.post('/enquiries/:enquiryId/notes',
  agentActionLimiter,
  param('enquiryId').isInt({ min: 1 }).withMessage('Valid enquiry ID required'),
  body('note').isLength({ min: 1, max: 2000 }).trim().withMessage('Note must be between 1-2000 characters'),
  body('note_type').optional().isIn(['internal', 'client_communication', 'follow_up_reminder']),
  body('communication_method').optional().isIn(['phone', 'email', 'whatsapp', 'in_person']),
  body('next_follow_up_date').optional().isISO8601(),
  audit.custom('agent_add_enquiry_note'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { enquiryId } = req.params;
    const agentId = req.user.id;
    const { note, note_type = 'internal', communication_method, next_follow_up_date } = req.body;

    const result = await executeTransaction(async (connection) => {
      // Verify agent is assigned to this enquiry
      const [enquiryCheck] = await connection.execute(
        'SELECT id FROM enquiries WHERE id = ? AND assigned_to = ?',
        [enquiryId, agentId]
      );

      if (enquiryCheck.length === 0) {
        throw new NotFoundError('Enquiry not found or not assigned to you');
      }

      // Add note
      const [noteResult] = await connection.execute(
        'INSERT INTO enquiry_notes (enquiry_id, user_id, note, note_type, communication_method, next_follow_up_date) VALUES (?, ?, ?, ?, ?, ?)',
        [enquiryId, agentId, note, note_type, communication_method, next_follow_up_date]
      );

      // Update enquiry first_response_at if this is the first response
      await connection.execute(`
        UPDATE enquiries 
        SET first_response_at = COALESCE(first_response_at, NOW()), updated_at = NOW()
        WHERE id = ?
      `, [enquiryId]);

      return {
        id: noteResult.insertId,
        enquiry_id: enquiryId,
        note,
        note_type,
        communication_method,
        next_follow_up_date,
        created_at: new Date().toISOString()
      };
    });

    res.status(201).json({
      success: true,
      message: 'Note added successfully',
      data: { note: result }
    });
  })
);

// ================================================================
// AGENT PROPERTY MANAGEMENT
// ================================================================

/**
 * Get properties assigned to agent
 * GET /api/agents/properties
 */
router.get('/properties',
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('status').optional().isIn(['active', 'sold', 'rented', 'withdrawn']),
  audit.custom('agent_view_assigned_properties'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status;
    const offset = (page - 1) * limit;

    let baseQuery = `
      SELECT 
        pl.id,
        pl.listing_id,
        pl.title,
        pl.property_type,
        pl.price,
        pl.area,
        pl.city,
        pl.location,
        pl.bedrooms,
        pl.bathrooms,
        pl.status,
        pl.main_image,
        pl.views_count,
        pl.favorites_count,
        pl.created_at,
        owner.name as owner_name,
        owner.email as owner_email,
        owner.phone as owner_phone
      FROM property_listings pl
      JOIN users owner ON pl.owner_id = owner.id
      WHERE pl.assigned_agent_id = ?
    `;

    const queryParams = [agentId];

    if (status) {
      baseQuery += ' AND pl.status = ?';
      queryParams.push(status);
    }

    // Get total count
    const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
    const [[{ total }]] = await executeQuery(countQuery, queryParams);

    // Get paginated results
    baseQuery += ' ORDER BY pl.created_at DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);

    const properties = await executeQuery(baseQuery, queryParams);

    res.json({
      success: true,
      data: {
        properties,
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

// ================================================================
// AGENT PERFORMANCE & ANALYTICS
// ================================================================

/**
 * Get agent performance metrics
 * GET /api/agents/performance
 */
router.get('/performance',
  query('date_from').optional().isISO8601(),
  query('date_to').optional().isISO8601(),
  audit.custom('agent_view_performance'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const { date_from, date_to } = req.query;

    // Build date filter
    let dateFilter = '';
    const queryParams = [agentId];

    if (date_from && date_to) {
      dateFilter = 'AND created_at >= ? AND created_at <= ?';
      queryParams.push(date_from, date_to);
    } else if (date_from) {
      dateFilter = 'AND created_at >= ?';
      queryParams.push(date_from);
    } else if (date_to) {
      dateFilter = 'AND created_at <= ?';
      queryParams.push(date_to);
    }

    const [performance] = await executeQuery(`
      SELECT 
        -- Enquiry metrics
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = ? ${dateFilter}) as total_enquiries,
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = ? AND status = 'resolved' ${dateFilter}) as resolved_enquiries,
        (SELECT AVG(TIMESTAMPDIFF(HOUR, created_at, resolved_at)) FROM enquiries 
         WHERE assigned_to = ? AND status = 'resolved' AND resolved_at IS NOT NULL ${dateFilter}) as avg_resolution_time_hours,
        
        -- Client metrics
        (SELECT COUNT(*) FROM user_agent_assignments WHERE agent_id = ? ${dateFilter}) as total_clients,
        (SELECT AVG(user_rating) FROM user_agent_assignments 
         WHERE agent_id = ? AND user_rating IS NOT NULL ${dateFilter}) as avg_client_rating,
        
        -- Property metrics
        (SELECT COUNT(*) FROM property_listings WHERE assigned_agent_id = ? ${dateFilter}) as assigned_properties,
        (SELECT COUNT(*) FROM property_listings WHERE assigned_agent_id = ? AND status IN ('sold', 'rented') ${dateFilter}) as closed_properties
    `, [
      agentId, agentId, agentId, agentId, agentId, agentId, agentId,
      ...(date_from && date_to ? [date_from, date_to, date_from, date_to, date_from, date_to, date_from, date_to, date_from, date_to, date_from, date_to, date_from, date_to] : 
         date_from ? [date_from, date_from, date_from, date_from, date_from, date_from, date_from] : 
         date_to ? [date_to, date_to, date_to, date_to, date_to, date_to, date_to] : [])
    ]);

    const metrics = performance[0];

    // Calculate derived metrics
    const enquiryResolutionRate = metrics.total_enquiries > 0 
      ? ((metrics.resolved_enquiries / metrics.total_enquiries) * 100).toFixed(1)
      : 0;

    const propertyClosureRate = metrics.assigned_properties > 0 
      ? ((metrics.closed_properties / metrics.assigned_properties) * 100).toFixed(1)
      : 0;

    res.json({
      success: true,
      data: {
        ...metrics,
        enquiry_resolution_rate: parseFloat(enquiryResolutionRate),
        property_closure_rate: parseFloat(propertyClosureRate),
        avg_resolution_time_hours: metrics.avg_resolution_time_hours ? parseFloat(metrics.avg_resolution_time_hours).toFixed(1) : null,
        avg_client_rating: metrics.avg_client_rating ? parseFloat(metrics.avg_client_rating).toFixed(1) : null,
        period: {
          from: date_from || 'all_time',
          to: date_to || 'present'
        }
      }
    });
  })
);

/**
 * Get agent's monthly statistics
 * GET /api/agents/stats/monthly
 */
router.get('/stats/monthly',
  query('months').optional().isInt({ min: 1, max: 12 }),
  audit.custom('agent_view_monthly_stats'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const months = parseInt(req.query.months) || 6;

    const [monthlyStats] = await executeQuery(`
      SELECT 
        DATE_FORMAT(created_at, '%Y-%m') as month,
        COUNT(*) as enquiries_count,
        SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count,
        AVG(CASE WHEN status = 'resolved' AND resolved_at IS NOT NULL 
            THEN TIMESTAMPDIFF(HOUR, created_at, resolved_at) ELSE NULL END) as avg_resolution_hours
      FROM enquiries 
      WHERE assigned_to = ? 
        AND created_at >= DATE_SUB(NOW(), INTERVAL ? MONTH)
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY month DESC
    `, [agentId, months]);

    const [clientStats] = await executeQuery(`
      SELECT 
        DATE_FORMAT(assigned_at, '%Y-%m') as month,
        COUNT(*) as new_clients,
        AVG(user_rating) as avg_rating
      FROM user_agent_assignments 
      WHERE agent_id = ? 
        AND assigned_at >= DATE_SUB(NOW(), INTERVAL ? MONTH)
      GROUP BY DATE_FORMAT(assigned_at, '%Y-%m')
      ORDER BY month DESC
    `, [agentId, months]);

    res.json({
      success: true,
      data: {
        enquiry_stats: monthlyStats,
        client_stats: clientStats,
        period_months: months
      }
    });
  })
);

// ================================================================
// AGENT PROFILE & SETTINGS
// ================================================================

/**
 * Get agent profile
 * GET /api/agents/profile
 */
router.get('/profile',
  audit.custom('agent_view_profile'),
  asyncHandler(async (req, res) => {
    const agentId = req.user.id;

    const [agents] = await executeQuery(`
      SELECT 
        id, uuid, name, email, phone, profile_image,
        license_number, agency_name, commission_rate, experience_years,
        specialization, agent_bio, agent_rating, total_sales,
        email_verified_at, phone_verified_at, status, created_at,
        created_by_admin_id
      FROM users 
      WHERE id = ? AND user_type = 'agent'
    `, [agentId]);

    if (agents.length === 0) {
      throw new NotFoundError('Agent profile not found');
    }

    const agent = agents[0];
    agent.email_verified = !!agent.email_verified_at;
    agent.phone_verified = !!agent.phone_verified_at;

    res.json({
      success: true,
      data: { agent }
    });
  })
);

/**
 * Update agent profile
 * PUT /api/agents/profile
 */
router.put('/profile',
  agentActionLimiter,
  body('name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('phone').optional().matches(/^\+?[1-9]\d{1,14}$/),
  body('agency_name').optional().isLength({ min: 2, max: 255 }).trim(),
  body('experience_years').optional().isInt({ min: 0, max: 50 }),
  body('specialization').optional().isLength({ max: 1000 }).trim(),
  body('agent_bio').optional().isLength({ max: 2000 }).trim(),
  audit.custom('agent_update_profile'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const updateData = req.body;

    const result = await executeTransaction(async (connection) => {
      // Get current agent data
      const [currentAgents] = await connection.execute(
        'SELECT * FROM users WHERE id = ? AND user_type = "agent"',
        [agentId]
      );

      if (currentAgents.length === 0) {
        throw new NotFoundError('Agent not found');
      }

      const currentAgent = currentAgents[0];

      // Check for phone number conflicts
      if (updateData.phone && updateData.phone !== currentAgent.phone) {
        const [phoneExists] = await connection.execute(
          'SELECT id FROM users WHERE phone = ? AND id != ?',
          [updateData.phone, agentId]
        );
        
        if (phoneExists.length > 0) {
          throw new DuplicateError('Phone number already in use');
        }
      }

      // Build update query
      const allowedFields = ['name', 'phone', 'agency_name', 'experience_years', 'specialization', 'agent_bio'];
      const updateFields = [];
      const updateValues = [];

      Object.entries(updateData).forEach(([key, value]) => {
        if (allowedFields.includes(key) && value !== undefined) {
          updateFields.push(`${key} = ?`);
          updateValues.push(value);
        }
      });

      if (updateFields.length === 0) {
        throw new ValidationError('No valid fields to update');
      }

      updateFields.push('updated_at = NOW()');
      updateValues.push(agentId);

      await connection.execute(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
        updateValues
      );

      // If phone number changed, reset phone verification
      if (updateData.phone && updateData.phone !== currentAgent.phone) {
        await connection.execute(
          'UPDATE users SET phone_verified_at = NULL, phone_verification_code = NULL WHERE id = ?',
          [agentId]
        );
      }

      // Get updated agent profile
      const [updatedAgents] = await connection.execute(
        'SELECT * FROM users WHERE id = ?',
        [agentId]
      );

      return {
        agent: updatedAgents[0],
        phoneVerificationReset: updateData.phone && updateData.phone !== currentAgent.phone
      };
    });

    res.json({
      success: true,
      message: 'Agent profile updated successfully',
      data: result
    });
  })
);

// ================================================================
// AGENT NOTIFICATIONS & PREFERENCES
// ================================================================

/**
 * Get agent notification preferences
 * GET /api/agents/notifications/preferences
 */
router.get('/notifications/preferences',
  audit.custom('agent_view_notification_preferences'),
  asyncHandler(async (req, res) => {
    const agentId = req.user.id;

    const [preferences] = await executeQuery(`
      SELECT 
        email_notifications, sms_notifications, push_notifications,
        notify_new_enquiry, notify_enquiry_update, notify_client_assignment,
        notify_property_update, notify_performance_report
      FROM user_notification_preferences 
      WHERE user_id = ?
    `, [agentId]);

    // If no preferences exist, return defaults
    const defaultPreferences = {
      email_notifications: true,
      sms_notifications: true,
      push_notifications: true,
      notify_new_enquiry: true,
      notify_enquiry_update: true,
      notify_client_assignment: true,
      notify_property_update: true,
      notify_performance_report: false
    };

    res.json({
      success: true,
      data: {
        preferences: preferences.length > 0 ? preferences[0] : defaultPreferences
      }
    });
  })
);

/**
 * Update agent notification preferences
 * PUT /api/agents/notifications/preferences
 */
router.put('/notifications/preferences',
  agentActionLimiter,
  body('email_notifications').optional().isBoolean(),
  body('sms_notifications').optional().isBoolean(),
  body('push_notifications').optional().isBoolean(),
  body('notify_new_enquiry').optional().isBoolean(),
  body('notify_enquiry_update').optional().isBoolean(),
  body('notify_client_assignment').optional().isBoolean(),
  body('notify_property_update').optional().isBoolean(),
  body('notify_performance_report').optional().isBoolean(),
  audit.custom('agent_update_notification_preferences'),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const agentId = req.user.id;
    const preferences = req.body;

    const result = await executeTransaction(async (connection) => {
      // Check if preferences exist
      const [existingPrefs] = await connection.execute(
        'SELECT id FROM user_notification_preferences WHERE user_id = ?',
        [agentId]
      );

      const allowedFields = [
        'email_notifications', 'sms_notifications', 'push_notifications',
        'notify_new_enquiry', 'notify_enquiry_update', 'notify_client_assignment',
        'notify_property_update', 'notify_performance_report'
      ];

      const updateFields = [];
      const updateValues = [];

      Object.entries(preferences).forEach(([key, value]) => {
        if (allowedFields.includes(key) && value !== undefined) {
          updateFields.push(`${key} = ?`);
          updateValues.push(value);
        }
      });

      if (updateFields.length === 0) {
        throw new ValidationError('No valid preferences to update');
      }

      if (existingPrefs.length > 0) {
        // Update existing preferences
        updateFields.push('updated_at = NOW()');
        updateValues.push(agentId);

        await connection.execute(
          `UPDATE user_notification_preferences SET ${updateFields.join(', ')} WHERE user_id = ?`,
          updateValues
        );
      } else {
        // Insert new preferences
        const fieldNames = updateFields.map(field => field.split(' = ')[0]);
        fieldNames.push('user_id', 'created_at', 'updated_at');
        updateValues.push(agentId, 'NOW()', 'NOW()');

        const placeholders = fieldNames.map(() => '?').join(', ');
        await connection.execute(
          `INSERT INTO user_notification_preferences (${fieldNames.join(', ')}) VALUES (${placeholders})`,
          updateValues
        );
      }

      return {
        updatedPreferences: preferences,
        updatedAt: new Date().toISOString()
      };
    });

    res.json({
      success: true,
      message: 'Notification preferences updated successfully',
      data: result
    });
  })
);

module.exports = router;