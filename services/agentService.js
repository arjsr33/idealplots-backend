// ================================================================
// BACKEND/SERVICES/AGENTSERVICE.JS - AGENT BUSINESS LOGIC
// Handles agent creation, management, and business operations
// ================================================================

const crypto = require('crypto');
const { 
  executeQuery, 
  executeTransaction, 
  executeStoredProcedure,
  buildPaginationQuery,
  buildSearchConditions,
  handleDatabaseError,
  logDatabaseOperation
} = require('../database/connection');

const { 
  hashPassword, 
  generateSecurePassword,
  generateVerificationToken,
  generateVerificationCode
} = require('../middleware/auth');

const {
  ValidationError,
  NotFoundError,
  DuplicateError,
  DatabaseError
} = require('../middleware/errorHandler');

const notificationService = require('./notificationService');

// ================================================================
// AGENT CREATION FUNCTIONS
// ================================================================

/**
 * Create agent account by admin
 * @param {number} adminId - Admin user ID
 * @param {Object} agentData - Agent information
 * @returns {Promise<Object>} Created agent details
 */
const createAgentByAdmin = async (adminId, agentData) => {
  return await executeTransaction(async (connection) => {
    try {
      const {
        name,
        email,
        phone,
        license_number,
        agency_name,
        commission_rate,
        experience_years,
        specialization = '',
        agent_bio = ''
      } = agentData;
      
      // Validate admin exists
      const [adminCheck] = await connection.execute(
        'SELECT id FROM users WHERE id = ? AND user_type = "admin" AND status = "active"',
        [adminId]
      );
      
      if (adminCheck.length === 0) {
        throw new ValidationError('Invalid admin user');
      }
      
      // Check for duplicate email
      const [emailCheck] = await connection.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );
      
      if (emailCheck.length > 0) {
        throw new DuplicateError('Email address already exists');
      }
      
      // Check for duplicate phone
      const [phoneCheck] = await connection.execute(
        'SELECT id FROM users WHERE phone = ?',
        [phone]
      );
      
      if (phoneCheck.length > 0) {
        throw new DuplicateError('Phone number already exists');
      }
      
      // Check for duplicate license number
      const [licenseCheck] = await connection.execute(
        'SELECT id FROM users WHERE license_number = ?',
        [license_number]
      );
      
      if (licenseCheck.length > 0) {
        throw new DuplicateError('License number already exists');
      }
      
      // Generate secure credentials
      const tempPassword = generateSecurePassword(12);
      const hashedPassword = await hashPassword(tempPassword);
      const emailToken = generateVerificationToken();
      const phoneCode = generateVerificationCode(6);
      
      // Call stored procedure to create agent
      const [procedureResult] = await connection.execute(
        'CALL AdminCreateAgentAccount(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, @agent_id, @success, @error_message)',
        [
          adminId,
          name,
          email,
          phone,
          hashedPassword,
          license_number,
          agency_name,
          parseFloat(commission_rate),
          parseInt(experience_years),
          specialization,
          agent_bio
        ]
      );
      
      // Get the output parameters
      const [[outputParams]] = await connection.execute(
        'SELECT @agent_id as agent_id, @success as success, @error_message as error_message'
      );
      
      if (!outputParams.success) {
        throw new DatabaseError(outputParams.error_message || 'Failed to create agent account');
      }
      
      const agentId = outputParams.agent_id;
      
      // Update verification tokens
      await connection.execute(
        `UPDATE users SET 
           email_verification_token = ?, 
           phone_verification_code = ?
         WHERE id = ?`,
        [emailToken, phoneCode, agentId]
      );
      
      // Get created agent details
      const [agentDetails] = await connection.execute(
        `SELECT 
           id, name, email, phone, license_number, agency_name, 
           commission_rate, experience_years, specialization, agent_bio,
           status, created_at, user_type
         FROM users 
         WHERE id = ?`,
        [agentId]
      );
      
      const agent = agentDetails[0];
      
      // Send notifications asynchronously
      const notificationResult = await notificationService.sendAgentAccountNotifications({
        agentId,
        adminId,
        agent,
        tempPassword,
        emailToken,
        phoneCode,
        connection
      });
      
      logDatabaseOperation('agent_created_by_admin', {
        agentId,
        adminId,
        email,
        agency_name
      });
      
      return {
        agent: {
          ...agent,
          email_verified: false,
          phone_verified: false
        },
        notifications: notificationResult,
        credentials: {
          tempPassword, // Include for admin reference (remove in production logs)
          emailToken,
          phoneCode
        }
      };
      
    } catch (error) {
      console.error('Error creating agent by admin:', error);
      
      if (error instanceof ValidationError || 
          error instanceof DuplicateError || 
          error instanceof DatabaseError) {
        throw error;
      }
      
      throw handleDatabaseError(error);
    }
  });
};

/**
 * Get agents created by admin
 * @param {number} adminId - Admin user ID
 * @param {Object} filters - Filter options
 * @returns {Promise<Object>} Paginated agent list
 */
const getAdminCreatedAgents = async (adminId, filters = {}) => {
  try {
    const {
      page = 1,
      limit = 10,
      status,
      search,
      verification_status
    } = filters;
    
    let baseQuery = `
      SELECT 
        u.id,
        u.name,
        u.email,
        u.phone,
        u.license_number,
        u.agency_name,
        u.commission_rate,
        u.experience_years,
        u.specialization,
        u.status,
        u.created_at,
        u.last_login_at,
        n.email_sent,
        n.sms_sent,
        n.email_sent_at,
        n.sms_sent_at,
        n.password_reset_required,
        CASE 
          WHEN u.email_verified_at IS NOT NULL AND u.phone_verified_at IS NOT NULL 
          THEN 'fully_verified'
          WHEN u.email_verified_at IS NOT NULL 
          THEN 'email_verified'
          WHEN u.phone_verified_at IS NOT NULL 
          THEN 'phone_verified'
          ELSE 'pending'
        END as verification_status,
        CASE 
          WHEN u.last_login_at IS NULL THEN 'never_logged_in'
          WHEN n.password_reset_required = 1 THEN 'password_reset_required'
          ELSE 'active'
        END as login_status
      FROM users u
      JOIN admin_created_notifications n ON u.id = n.user_id
      WHERE n.created_by_admin_id = ? AND u.user_type = 'agent'
    `;
    
    const queryParams = [adminId];
    
    // Add filters
    if (status) {
      baseQuery += ' AND u.status = ?';
      queryParams.push(status);
    }
    
    if (verification_status) {
      switch (verification_status) {
        case 'fully_verified':
          baseQuery += ' AND u.email_verified_at IS NOT NULL AND u.phone_verified_at IS NOT NULL';
          break;
        case 'email_verified':
          baseQuery += ' AND u.email_verified_at IS NOT NULL AND u.phone_verified_at IS NULL';
          break;
        case 'phone_verified':
          baseQuery += ' AND u.email_verified_at IS NULL AND u.phone_verified_at IS NOT NULL';
          break;
        case 'pending':
          baseQuery += ' AND u.email_verified_at IS NULL AND u.phone_verified_at IS NULL';
          break;
      }
    }
    
    if (search) {
      baseQuery += ` AND (
        u.name LIKE ? OR 
        u.email LIKE ? OR 
        u.phone LIKE ? OR 
        u.agency_name LIKE ? OR
        u.license_number LIKE ?
      )`;
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
    }
    
    // Build pagination query
    const { query: paginatedQuery, countQuery } = buildPaginationQuery(
      baseQuery,
      page,
      limit,
      'u.created_at DESC'
    );
    
    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;
    
    // Get paginated results
    const agents = await executeQuery(paginatedQuery, queryParams);
    
    return {
      agents,
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
    console.error('Error fetching admin created agents:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get agent details by ID
 * @param {number} agentId - Agent ID
 * @param {number} adminId - Admin ID
 * @returns {Promise<Object|null>} Agent details
 */
const getAgentDetails = async (agentId, adminId) => {
  try {
    const [agents] = await executeQuery(`
      SELECT 
        u.*,
        n.email_sent,
        n.sms_sent,
        n.email_sent_at,
        n.sms_sent_at,
        n.password_reset_required,
        n.created_at as account_created_at,
        CASE 
          WHEN u.email_verified_at IS NOT NULL AND u.phone_verified_at IS NOT NULL 
          THEN 'fully_verified'
          WHEN u.email_verified_at IS NOT NULL 
          THEN 'email_verified'
          WHEN u.phone_verified_at IS NOT NULL 
          THEN 'phone_verified'
          ELSE 'pending'
        END as verification_status,
        (SELECT COUNT(*) FROM user_agent_assignments WHERE agent_id = u.id AND status = 'active') as active_assignments,
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = u.id) as total_enquiries,
        (SELECT COUNT(*) FROM property_listings WHERE owner_id = u.id) as total_properties
      FROM users u
      JOIN admin_created_notifications n ON u.id = n.user_id
      WHERE u.id = ? AND n.created_by_admin_id = ? AND u.user_type = 'agent'
    `, [agentId, adminId]);
    
    return agents.length > 0 ? agents[0] : null;
    
  } catch (error) {
    console.error('Error fetching agent details:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Update agent by admin
 * @param {number} agentId - Agent ID
 * @param {number} adminId - Admin ID
 * @param {Object} updateData - Update data
 * @returns {Promise<Object>} Updated agent
 */
const updateAgentByAdmin = async (agentId, adminId, updateData) => {
  return await executeTransaction(async (connection) => {
    try {
      // Verify agent exists and was created by admin
      const [agentCheck] = await connection.execute(`
        SELECT u.id FROM users u
        JOIN admin_created_notifications n ON u.id = n.user_id
        WHERE u.id = ? AND n.created_by_admin_id = ? AND u.user_type = 'agent'
      `, [agentId, adminId]);
      
      if (agentCheck.length === 0) {
        throw new NotFoundError('Agent not found or not created by you');
      }
      
      // Build update query dynamically
      const allowedFields = [
        'name', 'phone', 'license_number', 'agency_name', 
        'commission_rate', 'experience_years', 'specialization', 
        'agent_bio', 'status'
      ];
      
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
      
      // Check for duplicates if email/phone/license is being updated
      if (updateData.phone) {
        const [phoneCheck] = await connection.execute(
          'SELECT id FROM users WHERE phone = ? AND id != ?',
          [updateData.phone, agentId]
        );
        if (phoneCheck.length > 0) {
          throw new DuplicateError('Phone number already exists');
        }
      }
      
      if (updateData.license_number) {
        const [licenseCheck] = await connection.execute(
          'SELECT id FROM users WHERE license_number = ? AND id != ?',
          [updateData.license_number, agentId]
        );
        if (licenseCheck.length > 0) {
          throw new DuplicateError('License number already exists');
        }
      }
      
      // Update agent
      updateFields.push('updated_at = NOW()');
      updateValues.push(agentId);
      
      await connection.execute(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
        updateValues
      );
      
      // Log the update
      await connection.execute(`
        INSERT INTO audit_logs (user_id, action, table_name, record_id, old_values, new_values, description)
        VALUES (?, 'update', 'users', ?, '{}', ?, 'Agent updated by admin')
      `, [adminId, agentId, JSON.stringify(updateData)]);
      
      // Get updated agent details
      const updatedAgent = await getAgentDetails(agentId, adminId);
      
      logDatabaseOperation('agent_updated_by_admin', {
        agentId,
        adminId,
        updatedFields: Object.keys(updateData)
      });
      
      return updatedAgent;
      
    } catch (error) {
      console.error('Error updating agent by admin:', error);
      throw handleDatabaseError(error);
    }
  });
};

/**
 * Deactivate agent account
 * @param {number} agentId - Agent ID
 * @param {number} adminId - Admin ID
 * @param {string} reason - Deactivation reason
 * @returns {Promise<Object>} Deactivation result
 */
const deactivateAgent = async (agentId, adminId, reason = '') => {
  return await executeTransaction(async (connection) => {
    try {
      // Verify agent exists and was created by admin
      const [agentCheck] = await connection.execute(`
        SELECT u.id, u.name, u.email FROM users u
        JOIN admin_created_notifications n ON u.id = n.user_id
        WHERE u.id = ? AND n.created_by_admin_id = ? AND u.user_type = 'agent'
      `, [agentId, adminId]);
      
      if (agentCheck.length === 0) {
        throw new NotFoundError('Agent not found or not created by you');
      }
      
      const agent = agentCheck[0];
      
      // Update agent status
      await connection.execute(
        'UPDATE users SET status = "inactive", updated_at = NOW() WHERE id = ?',
        [agentId]
      );
      
      // Deactivate all agent assignments
      await connection.execute(
        'UPDATE user_agent_assignments SET status = "inactive" WHERE agent_id = ?',
        [agentId]
      );
      
      // Log the deactivation
      await connection.execute(`
        INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, description)
        VALUES (?, 'deactivate', 'users', ?, ?, ?)
      `, [adminId, agentId, JSON.stringify({ reason }), `Agent deactivated: ${reason}`]);
      
      logDatabaseOperation('agent_deactivated_by_admin', {
        agentId,
        adminId,
        agentName: agent.name,
        reason
      });
      
      return {
        agentId,
        agentName: agent.name,
        agentEmail: agent.email,
        deactivatedAt: new Date().toISOString(),
        reason
      };
      
    } catch (error) {
      console.error('Error deactivating agent:', error);
      throw handleDatabaseError(error);
    }
  });
};

// ================================================================
// AGENT QUERY AND SEARCH FUNCTIONS
// ================================================================

/**
 * Search agents with filters
 * @param {Object} filters - Search filters
 * @returns {Promise<Object>} Search results
 */
const searchAgents = async (filters = {}) => {
  try {
    const {
      page = 1,
      limit = 10,
      search,
      status = 'active',
      agency_name,
      experience_min,
      experience_max,
      commission_min,
      commission_max,
      specialization,
      location,
      verified_only = false
    } = filters;
    
    let baseQuery = `
      SELECT 
        id, name, email, phone, license_number, agency_name,
        commission_rate, experience_years, specialization,
        status, created_at,
        CASE 
          WHEN email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL 
          THEN 'verified'
          ELSE 'unverified'
        END as verification_status
      FROM users 
      WHERE user_type = 'agent'
    `;
    
    const queryParams = [];
    
    // Status filter
    if (status) {
      baseQuery += ' AND status = ?';
      queryParams.push(status);
    }
    
    // Verification filter
    if (verified_only) {
      baseQuery += ' AND email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL';
    }
    
    // Search filter
    if (search) {
      baseQuery += ` AND (
        name LIKE ? OR 
        email LIKE ? OR 
        agency_name LIKE ? OR
        license_number LIKE ? OR
        specialization LIKE ?
      )`;
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
    }
    
    // Agency filter
    if (agency_name) {
      baseQuery += ' AND agency_name LIKE ?';
      queryParams.push(`%${agency_name}%`);
    }
    
    // Experience filters
    if (experience_min) {
      baseQuery += ' AND experience_years >= ?';
      queryParams.push(experience_min);
    }
    
    if (experience_max) {
      baseQuery += ' AND experience_years <= ?';
      queryParams.push(experience_max);
    }
    
    // Commission filters
    if (commission_min) {
      baseQuery += ' AND commission_rate >= ?';
      queryParams.push(commission_min);
    }
    
    if (commission_max) {
      baseQuery += ' AND commission_rate <= ?';
      queryParams.push(commission_max);
    }
    
    // Specialization filter
    if (specialization) {
      baseQuery += ' AND specialization LIKE ?';
      queryParams.push(`%${specialization}%`);
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
    const agents = await executeQuery(paginatedQuery, queryParams);
    
    return {
      agents,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      },
      filters: filters
    };
    
  } catch (error) {
    console.error('Error searching agents:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get agent statistics
 * @param {number} agentId - Agent ID
 * @returns {Promise<Object>} Agent statistics
 */
const getAgentStatistics = async (agentId) => {
  try {
    const [stats] = await executeQuery(`
      SELECT 
        (SELECT COUNT(*) FROM user_agent_assignments WHERE agent_id = ? AND status = 'active') as active_clients,
        (SELECT COUNT(*) FROM user_agent_assignments WHERE agent_id = ?) as total_clients,
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = ?) as total_enquiries,
        (SELECT COUNT(*) FROM enquiries WHERE assigned_to = ? AND status = 'resolved') as resolved_enquiries,
        (SELECT COUNT(*) FROM property_listings WHERE owner_id = ?) as listed_properties,
        (SELECT COUNT(*) FROM property_listings WHERE owner_id = ? AND status = 'approved') as approved_properties,
        (SELECT AVG(user_rating) FROM user_agent_assignments WHERE agent_id = ? AND user_rating IS NOT NULL) as avg_rating,
        (SELECT COUNT(*) FROM user_agent_assignments WHERE agent_id = ? AND user_rating IS NOT NULL) as total_ratings
    `, [agentId, agentId, agentId, agentId, agentId, agentId, agentId, agentId]);
    
    const statistics = stats[0];
    
    // Calculate performance metrics
    const enquiryResolutionRate = statistics.total_enquiries > 0 
      ? (statistics.resolved_enquiries / statistics.total_enquiries * 100).toFixed(2)
      : 0;
    
    const propertyApprovalRate = statistics.listed_properties > 0
      ? (statistics.approved_properties / statistics.listed_properties * 100).toFixed(2)
      : 0;
    
    return {
      ...statistics,
      enquiry_resolution_rate: parseFloat(enquiryResolutionRate),
      property_approval_rate: parseFloat(propertyApprovalRate),
      avg_rating: statistics.avg_rating ? parseFloat(statistics.avg_rating).toFixed(2) : null
    };
    
  } catch (error) {
    console.error('Error fetching agent statistics:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Get agents by agency
 * @param {string} agencyName - Agency name
 * @param {Object} options - Query options
 * @returns {Promise<Array>} List of agents
 */
const getAgentsByAgency = async (agencyName, options = {}) => {
  try {
    const { 
      status = 'active',
      verified_only = false,
      include_stats = false 
    } = options;
    
    let query = `
      SELECT 
        id, name, email, phone, license_number, 
        commission_rate, experience_years, specialization,
        status, created_at
      FROM users 
      WHERE user_type = 'agent' AND agency_name = ?
    `;
    
    const params = [agencyName];
    
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    
    if (verified_only) {
      query += ' AND email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL';
    }
    
    query += ' ORDER BY created_at DESC';
    
    const agents = await executeQuery(query, params);
    
    // Include statistics if requested
    if (include_stats && agents.length > 0) {
      const agentsWithStats = await Promise.all(
        agents.map(async (agent) => {
          const stats = await getAgentStatistics(agent.id);
          return { ...agent, statistics: stats };
        })
      );
      return agentsWithStats;
    }
    
    return agents;
    
  } catch (error) {
    console.error('Error fetching agents by agency:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// AGENT ASSIGNMENT FUNCTIONS
// ================================================================

/**
 * Assign agent to user
 * @param {number} userId - User ID
 * @param {number} agentId - Agent ID
 * @param {string} assignmentType - Assignment type
 * @param {string} reason - Assignment reason
 * @returns {Promise<Object>} Assignment result
 */
const assignAgentToUser = async (userId, agentId, assignmentType = 'manual', reason = '') => {
  return await executeTransaction(async (connection) => {
    try {
      // Verify user and agent exist
      const [userCheck] = await connection.execute(
        'SELECT id, name FROM users WHERE id = ? AND user_type = "user" AND status = "active"',
        [userId]
      );
      
      if (userCheck.length === 0) {
        throw new NotFoundError('User not found or inactive');
      }
      
      const [agentCheck] = await connection.execute(
        'SELECT id, name FROM users WHERE id = ? AND user_type = "agent" AND status = "active"',
        [agentId]
      );
      
      if (agentCheck.length === 0) {
        throw new NotFoundError('Agent not found or inactive');
      }
      
      // Check if assignment already exists
      const [existingAssignment] = await connection.execute(
        'SELECT id FROM user_agent_assignments WHERE user_id = ? AND agent_id = ? AND status = "active"',
        [userId, agentId]
      );
      
      if (existingAssignment.length > 0) {
        throw new DuplicateError('Agent is already assigned to this user');
      }
      
      // Deactivate any existing assignments for this user
      await connection.execute(
        'UPDATE user_agent_assignments SET status = "inactive" WHERE user_id = ? AND status = "active"',
        [userId]
      );
      
      // Create new assignment
      const [assignmentResult] = await connection.execute(`
        INSERT INTO user_agent_assignments (
          user_id, agent_id, assignment_type, assignment_reason, status
        ) VALUES (?, ?, ?, ?, 'active')
      `, [userId, agentId, assignmentType, reason]);
      
      const assignmentId = assignmentResult.insertId;
      
      // Update user's preferred agent
      await connection.execute(
        'UPDATE users SET preferred_agent_id = ? WHERE id = ?',
        [agentId, userId]
      );
      
      logDatabaseOperation('agent_assigned_to_user', {
        assignmentId,
        userId,
        agentId,
        assignmentType
      });
      
      return {
        assignmentId,
        userId,
        userName: userCheck[0].name,
        agentId,
        agentName: agentCheck[0].name,
        assignmentType,
        reason,
        assignedAt: new Date().toISOString()
      };
      
    } catch (error) {
      console.error('Error assigning agent to user:', error);
      throw handleDatabaseError(error);
    }
  });
};

/**
 * Get agent assignments
 * @param {number} agentId - Agent ID
 * @param {Object} filters - Filter options
 * @returns {Promise<Object>} Agent assignments
 */
const getAgentAssignments = async (agentId, filters = {}) => {
  try {
    const {
      page = 1,
      limit = 10,
      status = 'active'
    } = filters;
    
    const baseQuery = `
      SELECT 
        a.id as assignment_id,
        a.assignment_type,
        a.assignment_reason,
        a.status as assignment_status,
        a.assigned_at,
        a.last_contact_at,
        a.properties_shown,
        a.meetings_conducted,
        a.user_rating,
        u.id as user_id,
        u.name as user_name,
        u.email as user_email,
        u.phone as user_phone,
        u.created_at as user_joined_at
      FROM user_agent_assignments a
      JOIN users u ON a.user_id = u.id
      WHERE a.agent_id = ?
    `;
    
    const queryParams = [agentId];
    
    if (status) {
      baseQuery += ' AND a.status = ?';
      queryParams.push(status);
    }
    
    // Build pagination query
    const { query: paginatedQuery, countQuery } = buildPaginationQuery(
      baseQuery,
      page,
      limit,
      'a.assigned_at DESC'
    );
    
    // Get total count
    const [countResult] = await executeQuery(countQuery, queryParams);
    const total = countResult[0].total;
    
    // Get paginated results
    const assignments = await executeQuery(paginatedQuery, queryParams);
    
    return {
      assignments,
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
    console.error('Error fetching agent assignments:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core agent management
  createAgentByAdmin,
  getAdminCreatedAgents,
  getAgentDetails,
  updateAgentByAdmin,
  deactivateAgent,
  
  // Agent search and queries
  searchAgents,
  getAgentStatistics,
  getAgentsByAgency,
  
  // Agent assignments
  assignAgentToUser,
  getAgentAssignments
};