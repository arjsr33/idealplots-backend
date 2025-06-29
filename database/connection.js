// ================================================================
// BACKEND/DATABASE/CONNECTION.JS - SMART DATABASE CONNECTION MANAGER
// Centralized MySQL database connection with Docker/Hostinger support
// ================================================================

const mysql = require('mysql2/promise');
const path = require('path');

// ================================================================
// ENVIRONMENT-AWARE DATABASE CONFIGURATION
// ================================================================

const isProduction = process.env.NODE_ENV === 'production';
const isHostinger = isProduction; // Hostinger is our production environment

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'real_estate',
  
  // Environment-specific connection pool settings
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || (isProduction ? 10 : 5),
  queueLimit: parseInt(process.env.DB_QUEUE_LIMIT) || 0,
  acquireTimeout: parseInt(process.env.DB_ACQUIRE_TIMEOUT) || (isProduction ? 60000 : 30000),
  timeout: parseInt(process.env.DB_TIMEOUT) || (isProduction ? 60000 : 30000),
  
  // MySQL-specific settings
  charset: 'utf8mb4',
  timezone: '+00:00',
  
  // Connection behavior
  reconnect: true,
  idleTimeout: isProduction ? 300000 : 180000, // 5 min prod, 3 min dev
  maxReconnects: 10,
  
  // SSL configuration (Hostinger production)
  ssl: isHostinger && process.env.DB_SSL_REJECT_UNAUTHORIZED === 'true' ? {
    rejectUnauthorized: true
  } : false,
  
  // Additional options
  supportBigNumbers: true,
  bigNumberStrings: true,
  dateStrings: false,
  debug: process.env.DB_DEBUG === 'true',
  
  // SQL mode for strict data validation
  sql_mode: 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
  
  // Production optimizations
  typeCast: true,
  flags: isProduction ? [
    'COMPRESS',
    'PROTOCOL_41', 
    'TRANSACTIONS',
    'RESERVED',
    'SECURE_CONNECTION',
    'MULTI_STATEMENTS',
    'MULTI_RESULTS'
  ] : undefined
};

// ================================================================
// CONNECTION POOL INSTANCE
// ================================================================

let pool = null;
let connectionAttempts = 0;
const maxConnectionAttempts = 5;

// Create connection pool
const createPool = () => {
  try {
    pool = mysql.createPool(dbConfig);
    
    // Pool event handlers
    pool.on('connection', (connection) => {
      const env = isProduction ? 'PRODUCTION (Hostinger)' : 'DEVELOPMENT (Docker)';
      console.log(`✅ New database connection established: ${connection.threadId} [${env}]`);
      connectionAttempts = 0; // Reset attempts on successful connection
    });
    
    pool.on('error', (err) => {
      console.error('❌ Database pool error:', err.message);
      
      if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('🔄 Database connection lost, attempting to reconnect...');
        handleDisconnect();
      } else {
        console.error('❌ Unhandled database error:', err);
        // Don't throw in production to avoid crashes
        if (!isProduction) {
          throw err;
        }
      }
    });
    
    pool.on('acquire', (connection) => {
      if (process.env.DB_DEBUG === 'true') {
        console.log(`🔒 Connection ${connection.threadId} acquired`);
      }
    });
    
    pool.on('release', (connection) => {
      if (process.env.DB_DEBUG === 'true') {
        console.log(`🔓 Connection ${connection.threadId} released`);
      }
    });
    
    const env = isProduction ? 'PRODUCTION (Hostinger)' : 'DEVELOPMENT (Docker)';
    console.log(`📊 Database connection pool created successfully [${env}]`);
    console.log(`🔗 Connected to: ${dbConfig.user}@${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
    
    return pool;
    
  } catch (error) {
    console.error('❌ Failed to create database pool:', error);
    throw error;
  }
};

// Handle connection loss and reconnection
const handleDisconnect = () => {
  connectionAttempts++;
  
  if (connectionAttempts > maxConnectionAttempts) {
    console.error(`❌ Maximum connection attempts (${maxConnectionAttempts}) reached.`);
    if (isProduction) {
      // In production, try to restart gracefully
      console.log('🔄 Attempting to restart database pool...');
      setTimeout(() => {
        pool = null;
        createPool();
      }, 10000); // Wait 10 seconds before restart
    } else {
      process.exit(1);
    }
    return;
  }
  
  console.log(`🔄 Reconnection attempt ${connectionAttempts}/${maxConnectionAttempts}`);
  
  setTimeout(() => {
    try {
      pool = createPool();
    } catch (error) {
      console.error('❌ Failed to reconnect to database:', error);
      handleDisconnect();
    }
  }, 2000 * connectionAttempts); // Exponential backoff
};

// Initialize pool
createPool();

// ================================================================
// CONNECTION MANAGEMENT FUNCTIONS
// ================================================================

/**
 * Get a connection from the pool
 * @returns {Promise<Connection>} Database connection
 */
const getConnection = async () => {
  try {
    if (!pool) {
      console.log('🔄 Pool not initialized, creating new pool...');
      createPool();
    }
    
    const connection = await pool.getConnection();
    
    // Set session-specific configurations
    await connection.execute('SET SESSION sql_mode = ?', [dbConfig.sql_mode]);
    await connection.execute('SET SESSION time_zone = ?', [dbConfig.timezone]);
    
    return connection;
  } catch (error) {
    console.error('❌ Error getting database connection:', error.message);
    
    // Handle connection pool exhaustion
    if (error.code === 'POOL_CLOSED' || error.code === 'POOL_ENQUEUE_TIMEOUT') {
      console.log('🔄 Pool issue detected, recreating pool...');
      pool = null;
      createPool();
      // Retry once
      return await pool.getConnection();
    }
    
    throw error;
  }
};

/**
 * Execute a query with automatic connection management
 * @param {string} query - SQL query
 * @param {Array} params - Query parameters
 * @param {Object} options - Additional options
 * @returns {Promise<Array>} Query results
 */
const executeQuery = async (query, params = [], options = {}) => {
  let connection;
  
  try {
    connection = await getConnection();
    
    const startTime = Date.now();
    const [results] = await connection.execute(query, params);
    const executionTime = Date.now() - startTime;
    
    // Log slow queries in development
    if (process.env.NODE_ENV === 'development' && executionTime > 1000) {
      console.warn(`⚠️ Slow query detected (${executionTime}ms):`, query.substring(0, 100) + '...');
    }
    
    // Log database operations if enabled
    if (process.env.DB_LOG === 'true') {
      logDatabaseOperation('query_executed', {
        query: query.substring(0, 100) + '...',
        executionTime,
        rowsAffected: results.affectedRows || results.length
      });
    }
    
    return results;
    
  } catch (error) {
    console.error('❌ Database query error:', {
      query: query.substring(0, 100) + '...',
      params: params.length > 0 ? '[' + params.length + ' params]' : 'no params',
      error: error.message
    });
    throw handleDatabaseError(error, 'executeQuery');
  } finally {
    if (connection) {
      connection.release();
    }
  }
};

/**
 * Execute a transaction with automatic rollback on error
 * @param {Function} callback - Function containing transaction operations
 * @returns {Promise<any>} Transaction result
 */
const executeTransaction = async (callback) => {
  let connection;
  
  try {
    connection = await getConnection();
    await connection.beginTransaction();
    
    const startTime = Date.now();
    const result = await callback(connection);
    const executionTime = Date.now() - startTime;
    
    await connection.commit();
    
    if (process.env.DB_LOG === 'true') {
      logDatabaseOperation('transaction_completed', {
        executionTime,
        success: true
      });
    }
    
    return result;
    
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
        console.log('🔄 Transaction rolled back due to error');
      } catch (rollbackError) {
        console.error('❌ Error rolling back transaction:', rollbackError);
      }
    }
    
    console.error('❌ Transaction error:', error.message);
    throw handleDatabaseError(error, 'executeTransaction');
  } finally {
    if (connection) {
      connection.release();
    }
  }
};

/**
 * Execute stored procedure
 * @param {string} procedureName - Name of the stored procedure
 * @param {Array} params - Procedure parameters
 * @returns {Promise<Array>} Procedure results
 */
const executeStoredProcedure = async (procedureName, params = []) => {
  const placeholders = params.map(() => '?').join(', ');
  const query = `CALL ${procedureName}(${placeholders})`;
  
  return await executeQuery(query, params);
};

/**
 * Test database connection
 * @returns {Promise<boolean>} Connection status
 */
const testConnection = async () => {
  try {
    const connection = await getConnection();
    const [results] = await connection.execute('SELECT 1 as test, NOW() as timestamp, DATABASE() as db_name');
    connection.release();
    
    const isConnected = results && results[0] && results[0].test === 1;
    
    if (isConnected) {
      const env = isProduction ? 'PRODUCTION' : 'DEVELOPMENT';
      console.log(`✅ Database connection test passed [${env}]:`, {
        database: results[0].db_name,
        timestamp: results[0].timestamp,
        host: dbConfig.host,
        port: dbConfig.port
      });
    }
    
    return isConnected;
  } catch (error) {
    console.error('❌ Database connection test failed:', error.message);
    return false;
  }
};

/**
 * Get pool status information
 * @returns {Object} Pool status
 */
const getPoolStatus = () => {
  if (!pool) {
    return { status: 'not_initialized' };
  }
  
  try {
    return {
      status: 'active',
      environment: isProduction ? 'production' : 'development',
      totalConnections: pool.pool._allConnections.length,
      freeConnections: pool.pool._freeConnections.length,
      acquiredConnections: pool.pool._acquiredConnections.length,
      queuedRequests: pool.pool._connectionQueue.length,
      config: {
        host: dbConfig.host,
        port: dbConfig.port,
        database: dbConfig.database,
        connectionLimit: dbConfig.connectionLimit
      }
    };
  } catch (error) {
    return { 
      status: 'error', 
      error: error.message 
    };
  }
};

/**
 * Close all database connections
 * @returns {Promise<void>}
 */
const closeAllConnections = async () => {
  try {
    if (pool) {
      console.log('📴 Closing database connection pool...');
      await pool.end();
      console.log('✅ Database connection pool closed successfully');
      pool = null;
    }
  } catch (error) {
    console.error('❌ Error closing database connections:', error);
    throw error;
  }
};

// ================================================================
// QUERY BUILDERS AND HELPERS (Keep your existing functions)
// ================================================================

/**
 * Build pagination query
 * @param {string} baseQuery - Base SQL query
 * @param {number} page - Page number (1-based)
 * @param {number} limit - Items per page
 * @param {string} orderBy - Order by clause
 * @returns {Object} Query and count query
 */
const buildPaginationQuery = (baseQuery, page = 1, limit = 10, orderBy = '') => {
  const offset = (page - 1) * limit;
  
  let query = baseQuery;
  if (orderBy) {
    query += ` ORDER BY ${orderBy}`;
  }
  query += ` LIMIT ${limit} OFFSET ${offset}`;
  
  const countQuery = baseQuery.replace(/SELECT .+ FROM/, 'SELECT COUNT(*) as total FROM');
  
  return { query, countQuery };
};

/**
 * Escape string for LIKE queries
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
const escapeLikeString = (str) => {
  return str.replace(/[%_\\]/g, '\\$&');
};

/**
 * Build search conditions
 * @param {Object} searchParams - Search parameters
 * @param {Array} searchFields - Fields to search in
 * @returns {Object} WHERE clause and parameters
 */
const buildSearchConditions = (searchParams, searchFields) => {
  const conditions = [];
  const params = [];
  
  Object.entries(searchParams).forEach(([key, value]) => {
    if (value && searchFields.includes(key)) {
      if (typeof value === 'string') {
        conditions.push(`${key} LIKE ?`);
        params.push(`%${escapeLikeString(value)}%`);
      } else {
        conditions.push(`${key} = ?`);
        params.push(value);
      }
    }
  });
  
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  
  return { whereClause, params };
};

// ================================================================
// ERROR HANDLING AND LOGGING
// ================================================================

/**
 * Log database operation
 * @param {string} operation - Operation type
 * @param {Object} details - Operation details
 */
const logDatabaseOperation = (operation, details) => {
  if (process.env.NODE_ENV === 'development' || process.env.DB_LOG === 'true') {
    console.log(`🗄️ DB Operation: ${operation}`, details);
  }
};

/**
 * Handle database errors with environment-aware responses
 * @param {Error} error - Database error
 * @param {string} context - Error context
 * @returns {Error} Processed error
 */
const handleDatabaseError = (error, context = '') => {
  const errorDetails = {
    code: error.code,
    errno: error.errno,
    sqlState: error.sqlState,
    sqlMessage: error.sqlMessage,
    context,
    environment: isProduction ? 'production' : 'development'
  };
  
  // Log full details in development, limited in production
  if (isProduction) {
    console.error('❌ Database Error:', {
      code: error.code,
      context,
      timestamp: new Date().toISOString()
    });
  } else {
    console.error('❌ Database Error:', errorDetails);
  }
  
  // Map specific database errors to user-friendly messages
  switch (error.code) {
    case 'ER_DUP_ENTRY':
      error.userMessage = 'This record already exists';
      break;
    case 'ER_NO_REFERENCED_ROW_2':
      error.userMessage = 'Referenced record does not exist';
      break;
    case 'ER_ROW_IS_REFERENCED_2':
      error.userMessage = 'Cannot delete record as it is being used elsewhere';
      break;
    case 'ER_DATA_TOO_LONG':
      error.userMessage = 'Data is too long for the field';
      break;
    case 'ER_BAD_NULL_ERROR':
      error.userMessage = 'Required field is missing';
      break;
    case 'ECONNREFUSED':
      error.userMessage = 'Cannot connect to database';
      break;
    case 'ER_ACCESS_DENIED_ERROR':
      error.userMessage = 'Database access denied';
      break;
    default:
      error.userMessage = isProduction ? 'Database operation failed' : error.message;
  }
  
  return error;
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core functions
  getConnection,
  executeQuery,
  executeTransaction,
  executeStoredProcedure,
  testConnection,
  closeAllConnections,
  
  // Pool management
  getPoolStatus,
  
  // Query helpers
  buildPaginationQuery,
  buildSearchConditions,
  escapeLikeString,
  
  // Utilities
  logDatabaseOperation,
  handleDatabaseError,
  
  // Direct pool access (use with caution)
  pool: () => pool,
  
  // Configuration
  dbConfig,
  
  // Environment info
  isProduction,
  isHostinger
};