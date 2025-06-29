// ================================================================
// BACKEND/SERVICES/ENQUIRYSERVICE.JS - ENQUIRY MANAGEMENT SERVICE
// Business logic for enquiry processing, assignment, and follow-up
// ================================================================

const { 
  executeQuery, 
  executeTransaction, 
  handleDatabaseError 
} = require('../database/connection');

const { 
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

const notificationService = require('./notificationService');

// ================================================================
// ENQUIRY CREATION FUNCTIONS
// ================================================================

/**
 * Create new enquiry with optional account creation
 * @param {Object} enquiryData - Enquiry data
 * @param {boolean} createAccount - Whether to create account
 * @param {string} password - Password if creating account
 * @returns {Promise<Object>} Created enquiry and user data
 */
const createEnquiry = async (enquiryData, createAccount = false, password = null) => {
  const {
    name,
    email,
    phone,
    requirements,
    property_id,
    property_title,
    property_price,
    source = 'website',
    page_url,
    user_agent
  } = enquiryData;

  return await executeTransaction(async (connection) => {
    let userId = null;
    let accountCreated = false;

    // Check if user already exists
    const [existingUsers] = await connection.execute(`
      SELECT id, name, email FROM users 
      WHERE email = ? OR phone = ?
      LIMIT 1
    `, [email, phone]);

    if (existingUsers.length > 0) {
      userId = existingUsers[0].id;
    } else if (createAccount && password) {
      // Create new user account
      const hashedPassword = await hashPassword(password);
      const emailToken = generateVerificationToken();
      const phoneCode = generateVerificationCode(6);

      const [userResult] = await connection.execute(`
        INSERT INTO users (
          name, email, phone, password, user_type, status,
          email_verification_token, phone_verification_code,
          is_buyer, is_seller, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'user', 'pending_verification', ?, ?, TRUE, FALSE, NOW(), NOW())
      `, [name, email, phone, hashedPassword, emailToken, phoneCode]);

      userId = userResult.insertId;
      accountCreated = true;

      // Send verification notifications (async)
      try {
        await notificationService.sendEmail({
          to: email,
          subject: 'Welcome to Ideal Plots - Verify Your Email',
          html: notificationService.emailTemplates.emailVerification({
            name,
            token: emailToken,
            verificationUrl: `${process.env.FRONTEND_URL}/verify-email?token=${emailToken}`
          }).html
        });
      } catch (error) {
        console.error('Failed to send verification email:', error);
      }

      try {
        await notificationService.sendSMS({
          to: phone,
          body: notificationService.smsTemplates.phoneVerification({ code: phoneCode })
        });
      } catch (error) {
        console.error('Failed to send verification SMS:', error);
      }
    }

    // Create enquiry record
    const [enquiryResult] = await connection.execute(`
      INSERT INTO enquiries (
        user_id, name, email, phone, requirements, property_id, property_title, property_price,
        source, page_url, user_agent, account_creation_offered, account_created_during_enquiry,
        status, priority, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', 'medium', NOW(), NOW())
    `, [
      userId, name, email, phone, requirements, property_id, property_title, property_price,
      source, page_url, user_agent, createAccount, accountCreated
    ]);

    const enquiryId = enquiryResult.insertId;

    // Update property inquiry count if property specified
    if (property_id) {
      await connection.execute(`
        UPDATE property_listings 
        SET inquiries_count = inquiries_count + 1 
        WHERE id = ?
      `, [property_id]);
    }

    // Get the created enquiry with ticket number
    const [newEnquiry] = await connection.execute(`
      SELECT id, ticket_number, user_id, name, email, phone, requirements,
             property_id, property_title, property_price, source, status, priority,
             account_created_during_enquiry, created_at
      FROM enquiries 
      WHERE id = ?
    `, [enquiryId]);

    // Auto-assign to available agent if enabled
    const assignedAgent = await autoAssignAgent(connection, enquiryId, requirements, property_id);

    return {
      enquiry: newEnquiry[0],
      user_id: userId,
      account_created: accountCreated,
      assigned_agent: assignedAgent
    };
  });
};

/**
 * Auto-assign enquiry to best available agent
 * @param {Object} connection - Database connection
 * @param {number} enquiryId - Enquiry ID
 * @param {string} requirements - Enquiry requirements
 * @param {number} propertyId - Property ID if applicable
 * @returns {Promise<Object|null>} Assigned agent info
 */
const autoAssignAgent = async (connection, enquiryId, requirements, propertyId = null) => {
  try {
    // Get system setting for auto-assignment
    const [settings] = await connection.execute(`
      SELECT setting_value FROM system_settings 
      WHERE setting_key = 'auto_assign_agents'
    `);

    if (settings.length === 0 || settings[0].setting_value !== 'true') {
      return null;
    }

    // Find best available agent
    let agentQuery = `
      SELECT u.id, u.name, u.email, u.phone, u.agency_name,
             u.agent_rating, u.specialization,
             COUNT(e.id) as current_enquiries
      FROM users u
      LEFT JOIN enquiries e ON u.id = e.assigned_to AND e.status IN ('new', 'assigned', 'in_progress')
      WHERE u.user_type = 'agent' 
        AND u.status = 'active'
        AND u.email_verified_at IS NOT NULL
    `;

    const queryParams = [];

    // If property-specific, prefer agents with matching specialization
    if (propertyId) {
      const [properties] = await connection.execute(`
        SELECT property_type FROM property_listings WHERE id = ?
      `, [propertyId]);

      if (properties.length > 0) {
        const propertyType = properties[0].property_type;
        agentQuery += ` AND (u.specialization IS NULL OR u.specialization LIKE ?)`;
        queryParams.push(`%${propertyType}%`);
      }
    }

    agentQuery += `
      GROUP BY u.id
      ORDER BY u.agent_rating DESC, current_enquiries ASC
      LIMIT 1
    `;

    const [agents] = await connection.execute(agentQuery, queryParams);

    if (agents.length === 0) {
      return null;
    }

    const agent = agents[0];

    // Assign enquiry to agent
    await connection.execute(`
      UPDATE enquiries 
      SET assigned_to = ?, status = 'assigned', updated_at = NOW()
      WHERE id = ?
    `, [agent.id, enquiryId]);

    // Send notification to agent
    try {
      await notificationService.sendEmail({
        to: agent.email,
        subject: 'New Enquiry Assigned - Ideal Plots',
        html: notificationService.emailTemplates.agentEnquiryAssignment({
          agentName: agent.name,
          enquiryId: enquiryId,
          requirements: requirements.substring(0, 200) + (requirements.length > 200 ? '...' : ''),
          dashboardUrl: `${process.env.FRONTEND_URL}/agent/enquiries/${enquiryId}`
        }).html
      });
    } catch (error) {
      console.error('Failed to send agent notification:', error);
    }

    return {
      id: agent.id,
      name: agent.name,
      email: agent.email,
      agency_name: agent.agency_name
    };

  } catch (error) {
    console.error('Auto-assignment failed:', error);
    return null;
  }
};

// ================================================================
// ENQUIRY RETRIEVAL FUNCTIONS
// ================================================================

/**
 * Get enquiries with filtering and pagination
 * @param {Object} filters - Filter options
 * @param {Object} pagination - Pagination options
 * @returns {Promise<Object>} Enquiries and pagination info
 */
const getEnquiries = async (filters = {}, pagination = { page: 1, limit: 10 }) => {
  const {
    status,
    priority,
    assigned_to,
    user_id,
    property_id,
    search,
    date_from,
    date_to,
    source
  } = filters;

  const { page, limit } = pagination;
  const offset = (page - 1) * limit;

  let baseQuery = `
    SELECT 
      e.id, e.ticket_number, e.user_id, e.name, e.email, e.phone,
      e.requirements, e.property_id, e.property_title, e.property_price,
      e.source, e.page_url, e.status, e.priority, e.assigned_to,
      e.first_response_at, e.resolved_at, e.customer_satisfaction_rating,
      e.account_created_during_enquiry, e.created_at, e.updated_at,
      
      -- User details (if account exists)
      u.name as user_name, u.uuid as user_uuid, u.profile_image,
      
      -- Assigned agent details
      agent.name as agent_name, agent.email as agent_email, 
      agent.phone as agent_phone, agent.agency_name,
      
      -- Property details
      pl.title as property_full_title, pl.city as property_city, 
      pl.location as property_location, pl.main_image as property_image,
      
      -- Enquiry notes count
      (SELECT COUNT(*) FROM enquiry_notes en WHERE en.enquiry_id = e.id) as notes_count,
      
      -- Latest note
      (SELECT note FROM enquiry_notes en WHERE en.enquiry_id = e.id 
       ORDER BY en.created_at DESC LIMIT 1) as latest_note
       
    FROM enquiries e
    LEFT JOIN users u ON e.user_id = u.id
    LEFT JOIN users agent ON e.assigned_to = agent.id
    LEFT JOIN property_listings pl ON e.property_id = pl.id
    WHERE 1=1
  `;

  const queryParams = [];

  // Apply filters
  if (status) {
    baseQuery += ' AND e.status = ?';
    queryParams.push(status);
  }

  if (priority) {
    baseQuery += ' AND e.priority = ?';
    queryParams.push(priority);
  }

  if (assigned_to) {
    baseQuery += ' AND e.assigned_to = ?';
    queryParams.push(assigned_to);
  }

  if (user_id) {
    baseQuery += ' AND e.user_id = ?';
    queryParams.push(user_id);
  }

  if (property_id) {
    baseQuery += ' AND e.property_id = ?';
    queryParams.push(property_id);
  }

  if (source) {
    baseQuery += ' AND e.source = ?';
    queryParams.push(source);
  }

  if (search) {
    baseQuery += ' AND (e.name LIKE ? OR e.email LIKE ? OR e.phone LIKE ? OR e.requirements LIKE ? OR e.ticket_number LIKE ?)';
    const searchTerm = `%${search}%`;
    queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
  }

  if (date_from) {
    baseQuery += ' AND e.created_at >= ?';
    queryParams.push(date_from);
  }

  if (date_to) {
    baseQuery += ' AND e.created_at <= ?';
    queryParams.push(date_to + ' 23:59:59');
  }

  // Get total count
  const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
  const [[{ total }]] = await executeQuery(countQuery, queryParams);

  // Get paginated results
  baseQuery += ' ORDER BY e.created_at DESC LIMIT ? OFFSET ?';
  queryParams.push(limit, offset);

  const enquiries = await executeQuery(baseQuery, queryParams);

  return {
    enquiries,
    pagination: {
      page,
      limit,
      total: parseInt(total),
      pages: Math.ceil(total / limit),
      hasNext: page < Math.ceil(total / limit),
      hasPrev: page > 1
    }
  };
};

/**
 * Get single enquiry by ID or ticket number
 * @param {string|number} identifier - Enquiry ID or ticket number
 * @param {boolean} includeNotes - Whether to include notes
 * @returns {Promise<Object>} Enquiry details
 */
const getEnquiryDetails = async (identifier, includeNotes = true) => {
  const isTicketNumber = typeof identifier === 'string' && identifier.startsWith('TKT-');
  
  const query = `
    SELECT 
      e.id, e.ticket_number, e.user_id, e.name, e.email, e.phone,
      e.requirements, e.property_id, e.property_title, e.property_price,
      e.source, e.page_url, e.user_agent, e.status, e.priority,
      e.assigned_to, e.first_response_at, e.resolved_at, e.resolution_notes,
      e.customer_satisfaction_rating, e.account_creation_offered,
      e.account_created_during_enquiry, e.created_at, e.updated_at,
      
      -- User details
      u.name as user_name, u.uuid as user_uuid, u.email as user_email,
      u.phone as user_phone, u.profile_image, u.is_buyer, u.is_seller,
      u.preferred_property_types, u.budget_min, u.budget_max, u.preferred_cities,
      
      -- Assigned agent details
      agent.name as agent_name, agent.email as agent_email,
      agent.phone as agent_phone, agent.agency_name, agent.license_number,
      
      -- Property details
      pl.title as property_full_title, pl.description as property_description,
      pl.property_type, pl.price as property_current_price, pl.area,
      pl.city as property_city, pl.location as property_location,
      pl.bedrooms, pl.bathrooms, pl.main_image as property_image,
      pl.status as property_status,
      
      -- Property owner details
      owner.name as property_owner_name, owner.phone as property_owner_phone
      
    FROM enquiries e
    LEFT JOIN users u ON e.user_id = u.id
    LEFT JOIN users agent ON e.assigned_to = agent.id
    LEFT JOIN property_listings pl ON e.property_id = pl.id
    LEFT JOIN users owner ON pl.owner_id = owner.id
    WHERE ${isTicketNumber ? 'e.ticket_number' : 'e.id'} = ?
  `;

  const [enquiries] = await executeQuery(query, [identifier]);

  if (enquiries.length === 0) {
    throw new NotFoundError('Enquiry not found');
  }

  const enquiry = enquiries[0];

  // Parse SET fields if user exists
  if (enquiry.user_id && enquiry.preferred_property_types) {
    enquiry.preferred_property_types = enquiry.preferred_property_types.split(',');
  }
  if (enquiry.user_id && enquiry.preferred_cities) {
    enquiry.preferred_cities = enquiry.preferred_cities.split(',');
  }

  // Get notes if requested
  if (includeNotes) {
    const [notes] = await executeQuery(`
      SELECT 
        en.id, en.note, en.note_type, en.communication_method,
        en.next_follow_up_date, en.created_at, en.updated_at,
        u.name as author_name, u.user_type as author_type
      FROM enquiry_notes en
      JOIN users u ON en.user_id = u.id
      WHERE en.enquiry_id = ?
      ORDER BY en.created_at DESC
    `, [enquiry.id]);

    enquiry.notes = notes;
  }

  return enquiry;
};

// ================================================================
// ENQUIRY UPDATE FUNCTIONS
// ================================================================

/**
 * Update enquiry status and details
 * @param {number} enquiryId - Enquiry ID
 * @param {Object} updates - Update data
 * @param {number} updatedBy - User ID making the update
 * @returns {Promise<Object>} Updated enquiry
 */
const updateEnquiry = async (enquiryId, updates, updatedBy) => {
  const {
    status,
    priority,
    assigned_to,
    resolution_notes,
    customer_satisfaction_rating
  } = updates;

  const updateFields = [];
  const updateValues = [];

  if (status !== undefined) {
    updateFields.push('status = ?');
    updateValues.push(status);
    
    // Set resolved_at if resolving
    if (status === 'resolved') {
      updateFields.push('resolved_at = NOW()');
    }
    
    // Set first_response_at if this is first response
    if (status !== 'new' && !updates.first_response_at) {
      updateFields.push('first_response_at = COALESCE(first_response_at, NOW())');
    }
  }

  if (priority !== undefined) {
    updateFields.push('priority = ?');
    updateValues.push(priority);
  }

  if (assigned_to !== undefined) {
    updateFields.push('assigned_to = ?');
    updateValues.push(assigned_to);
  }

  if (resolution_notes !== undefined) {
    updateFields.push('resolution_notes = ?');
    updateValues.push(resolution_notes);
  }

  if (customer_satisfaction_rating !== undefined) {
    updateFields.push('customer_satisfaction_rating = ?');
    updateValues.push(customer_satisfaction_rating);
  }

  if (updateFields.length === 0) {
    throw new ValidationError('No valid update fields provided');
  }

  updateFields.push('updated_at = NOW()');
  updateValues.push(enquiryId);

  await executeQuery(`
    UPDATE enquiries 
    SET ${updateFields.join(', ')}
    WHERE id = ?
  `, updateValues);

  // Log the update as a system note
  if (status || assigned_to || resolution_notes) {
    let noteText = 'Enquiry updated:';
    if (status) noteText += ` Status changed to ${status}.`;
    if (assigned_to) noteText += ` Assigned to agent.`;
    if (resolution_notes) noteText += ` Resolution notes added.`;

    await addEnquiryNote(enquiryId, noteText, updatedBy, 'system');
  }

  return await getEnquiryDetails(enquiryId, false);
};

/**
 * Assign enquiry to agent
 * @param {number} enquiryId - Enquiry ID
 * @param {number} agentId - Agent ID
 * @param {number} assignedBy - User ID making the assignment
 * @param {string} reason - Assignment reason
 * @returns {Promise<Object>} Updated enquiry
 */
const assignEnquiry = async (enquiryId, agentId, assignedBy, reason = null) => {
  return await executeTransaction(async (connection) => {
    // Verify agent exists and is active
    const [agents] = await connection.execute(`
      SELECT id, name, email, phone, agency_name 
      FROM users 
      WHERE id = ? AND user_type = 'agent' AND status = 'active'
    `, [agentId]);

    if (agents.length === 0) {
      throw new ValidationError('Invalid or inactive agent');
    }

    const agent = agents[0];

    // Update enquiry
    await connection.execute(`
      UPDATE enquiries 
      SET assigned_to = ?, status = 'assigned', updated_at = NOW()
      WHERE id = ?
    `, [agentId, enquiryId]);

    // Add assignment note
    const noteText = `Enquiry assigned to ${agent.name} (${agent.agency_name || 'Independent'})${reason ? `. Reason: ${reason}` : ''}`;
    await connection.execute(`
      INSERT INTO enquiry_notes (enquiry_id, user_id, note, note_type, created_at, updated_at)
      VALUES (?, ?, ?, 'system', NOW(), NOW())
    `, [enquiryId, assignedBy, noteText]);

    // Send notification to agent
    try {
      const [enquiries] = await connection.execute(`
        SELECT ticket_number, requirements FROM enquiries WHERE id = ?
      `, [enquiryId]);

      if (enquiries.length > 0) {
        await notificationService.sendEmail({
          to: agent.email,
          subject: `New Enquiry Assigned - ${enquiries[0].ticket_number}`,
          html: notificationService.emailTemplates.agentEnquiryAssignment({
            agentName: agent.name,
            ticketNumber: enquiries[0].ticket_number,
            requirements: enquiries[0].requirements.substring(0, 200),
            dashboardUrl: `${process.env.FRONTEND_URL}/agent/enquiries/${enquiryId}`
          }).html
        });
      }
    } catch (error) {
      console.error('Failed to send assignment notification:', error);
    }

    return await getEnquiryDetails(enquiryId, false);
  });
};

// ================================================================
// ENQUIRY NOTES FUNCTIONS
// ================================================================

/**
 * Add note to enquiry
 * @param {number} enquiryId - Enquiry ID
 * @param {string} note - Note text
 * @param {number} userId - User ID adding the note
 * @param {string} noteType - Note type
 * @param {string} communicationMethod - Communication method
 * @param {string} nextFollowUpDate - Next follow-up date
 * @returns {Promise<Object>} Created note
 */
const addEnquiryNote = async (
  enquiryId, 
  note, 
  userId, 
  noteType = 'internal', 
  communicationMethod = null, 
  nextFollowUpDate = null
) => {
  const [result] = await executeQuery(`
    INSERT INTO enquiry_notes (
      enquiry_id, user_id, note, note_type, communication_method,
      next_follow_up_date, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
  `, [enquiryId, userId, note, noteType, communicationMethod, nextFollowUpDate]);

  // Get the created note with user details
  const [notes] = await executeQuery(`
    SELECT 
      en.id, en.note, en.note_type, en.communication_method,
      en.next_follow_up_date, en.created_at, en.updated_at,
      u.name as author_name, u.user_type as author_type
    FROM enquiry_notes en
    JOIN users u ON en.user_id = u.id
    WHERE en.id = ?
  `, [result.insertId]);

  return notes[0];
};

/**
 * Get enquiry notes
 * @param {number} enquiryId - Enquiry ID
 * @param {Object} filters - Filter options
 * @returns {Promise<Array>} Enquiry notes
 */
const getEnquiryNotes = async (enquiryId, filters = {}) => {
  const { noteType, userId, limit = 50 } = filters;

  let query = `
    SELECT 
      en.id, en.note, en.note_type, en.communication_method,
      en.next_follow_up_date, en.created_at, en.updated_at,
      u.name as author_name, u.user_type as author_type,
      u.profile_image as author_image
    FROM enquiry_notes en
    JOIN users u ON en.user_id = u.id
    WHERE en.enquiry_id = ?
  `;

  const queryParams = [enquiryId];

  if (noteType) {
    query += ' AND en.note_type = ?';
    queryParams.push(noteType);
  }

  if (userId) {
    query += ' AND en.user_id = ?';
    queryParams.push(userId);
  }

  query += ' ORDER BY en.created_at DESC LIMIT ?';
  queryParams.push(limit);

  const notes = await executeQuery(query, queryParams);
  return notes;
};

// ================================================================
// ANALYTICS FUNCTIONS
// ================================================================

/**
 * Get enquiry analytics
 * @param {Object} filters - Filter options
 * @returns {Promise<Object>} Analytics data
 */
const getEnquiryAnalytics = async (filters = {}) => {
  const { dateFrom, dateTo, agentId, status } = filters;

  let baseWhere = 'WHERE 1=1';
  const queryParams = [];

  if (dateFrom) {
    baseWhere += ' AND e.created_at >= ?';
    queryParams.push(dateFrom);
  }

  if (dateTo) {
    baseWhere += ' AND e.created_at <= ?';
    queryParams.push(dateTo + ' 23:59:59');
  }

  if (agentId) {
    baseWhere += ' AND e.assigned_to = ?';
    queryParams.push(agentId);
  }

  if (status) {
    baseWhere += ' AND e.status = ?';
    queryParams.push(status);
  }

  // Basic counts
  const [counts] = await executeQuery(`
    SELECT 
      COUNT(*) as total_enquiries,
      COUNT(CASE WHEN status = 'new' THEN 1 END) as new_enquiries,
      COUNT(CASE WHEN status = 'assigned' THEN 1 END) as assigned_enquiries,
      COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress_enquiries,
      COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_enquiries,
      COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed_enquiries,
      COUNT(CASE WHEN assigned_to IS NOT NULL THEN 1 END) as assigned_count,
      COUNT(CASE WHEN account_created_during_enquiry = TRUE THEN 1 END) as accounts_created,
      AVG(customer_satisfaction_rating) as avg_rating
    FROM enquiries e
    ${baseWhere}
  `, queryParams);

  // Response time analytics
  const [responseTimes] = await executeQuery(`
    SELECT 
      AVG(TIMESTAMPDIFF(HOUR, created_at, first_response_at)) as avg_first_response_hours,
      AVG(TIMESTAMPDIFF(HOUR, created_at, resolved_at)) as avg_resolution_hours,
      COUNT(CASE WHEN first_response_at IS NOT NULL THEN 1 END) as responded_count,
      COUNT(CASE WHEN resolved_at IS NOT NULL THEN 1 END) as resolved_count
    FROM enquiries e
    ${baseWhere}
  `, queryParams);

  // Source analytics
  const sources = await executeQuery(`
    SELECT 
      source,
      COUNT(*) as count,
      COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_count
    FROM enquiries e
    ${baseWhere}
    GROUP BY source
    ORDER BY count DESC
  `, queryParams);

  // Priority distribution
  const priorities = await executeQuery(`
    SELECT 
      priority,
      COUNT(*) as count,
      COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_count
    FROM enquiries e
    ${baseWhere}
    GROUP BY priority
    ORDER BY 
      CASE priority 
        WHEN 'urgent' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        WHEN 'low' THEN 4 
      END
  `, queryParams);

  // Daily trends (last 30 days)
  const trends = await executeQuery(`
    SELECT 
      DATE(created_at) as date,
      COUNT(*) as enquiries_count,
      COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_count
    FROM enquiries e
    ${baseWhere} AND e.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY DATE(created_at)
    ORDER BY date ASC
  `, queryParams);

  return {
    summary: {
      ...counts[0],
      assignment_rate: counts[0].total_enquiries > 0 
        ? ((counts[0].assigned_count / counts[0].total_enquiries) * 100).toFixed(1)
        : 0,
      resolution_rate: counts[0].total_enquiries > 0
        ? ((counts[0].resolved_enquiries / counts[0].total_enquiries) * 100).toFixed(1)
        : 0
    },
    performance: {
      ...responseTimes[0],
      avg_first_response_hours: responseTimes[0].avg_first_response_hours 
        ? parseFloat(responseTimes[0].avg_first_response_hours).toFixed(1)
        : null,
      avg_resolution_hours: responseTimes[0].avg_resolution_hours
        ? parseFloat(responseTimes[0].avg_resolution_hours).toFixed(1)
        : null
    },
    distributions: {
      sources,
      priorities
    },
    trends
  };
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core functions
  createEnquiry,
  getEnquiries,
  getEnquiryDetails,
  updateEnquiry,
  assignEnquiry,
  
  // Notes management
  addEnquiryNote,
  getEnquiryNotes,
  
  // Analytics
  getEnquiryAnalytics,
  
  // Utility functions
  autoAssignAgent
};