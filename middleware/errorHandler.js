// ================================================================
// BACKEND/MIDDLEWARE/ERRORHANDLER.JS - GLOBAL ERROR HANDLER
// Centralized error handling with logging and user-friendly responses
// ================================================================

const fs = require('fs').promises;
const path = require('path');

// ================================================================
// ERROR TYPES AND CODES
// ================================================================

const ERROR_TYPES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR: 'NOT_FOUND_ERROR',
  DUPLICATE_ERROR: 'DUPLICATE_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  FILE_UPLOAD_ERROR: 'FILE_UPLOAD_ERROR',
  RATE_LIMIT_ERROR: 'RATE_LIMIT_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR'
};

const HTTP_STATUS_CODES = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503
};

// ================================================================
// CUSTOM ERROR CLASSES
// ================================================================

class AppError extends Error {
  constructor(message, statusCode, errorType = ERROR_TYPES.INTERNAL_ERROR, details = null) {
    super(message);
    
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorType = errorType;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, HTTP_STATUS_CODES.BAD_REQUEST, ERROR_TYPES.VALIDATION_ERROR, details);
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, HTTP_STATUS_CODES.UNAUTHORIZED, ERROR_TYPES.AUTHENTICATION_ERROR);
  }
}

class AuthorizationError extends AppError {
  constructor(message = 'Access denied') {
    super(message, HTTP_STATUS_CODES.FORBIDDEN, ERROR_TYPES.AUTHORIZATION_ERROR);
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, HTTP_STATUS_CODES.NOT_FOUND, ERROR_TYPES.NOT_FOUND_ERROR);
  }
}

class DuplicateError extends AppError {
  constructor(message = 'Resource already exists') {
    super(message, HTTP_STATUS_CODES.CONFLICT, ERROR_TYPES.DUPLICATE_ERROR);
  }
}

class DatabaseError extends AppError {
  constructor(message = 'Database operation failed', details = null) {
    super(message, HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, ERROR_TYPES.DATABASE_ERROR, details);
  }
}

class ExternalServiceError extends AppError {
  constructor(message = 'External service error', statusCode = HTTP_STATUS_CODES.BAD_GATEWAY) {
    super(message, statusCode, ERROR_TYPES.EXTERNAL_SERVICE_ERROR);
  }
}

class FileUploadError extends AppError {
  constructor(message = 'File upload failed') {
    super(message, HTTP_STATUS_CODES.BAD_REQUEST, ERROR_TYPES.FILE_UPLOAD_ERROR);
  }
}

class RateLimitError extends AppError {
  constructor(message = 'Too many requests') {
    super(message, HTTP_STATUS_CODES.TOO_MANY_REQUESTS, ERROR_TYPES.RATE_LIMIT_ERROR);
  }
}

// ================================================================
// ERROR LOGGING
// ================================================================

/**
 * Log error to file and console
 * @param {Error} error - Error object
 * @param {Object} req - Express request object
 * @param {string} level - Log level (error, warn, info)
 */
const logError = async (error, req = null, level = 'error') => {
  const timestamp = new Date().toISOString();
  const errorId = generateErrorId();
  
  const logEntry = {
    id: errorId,
    timestamp,
    level,
    message: error.message,
    stack: error.stack,
    type: error.errorType || 'UNKNOWN_ERROR',
    statusCode: error.statusCode || 500,
    details: error.details || null,
    request: req ? {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id || null,
      body: sanitizeRequestBody(req.body),
      params: req.params,
      query: req.query
    } : null,
    environment: process.env.NODE_ENV || 'development',
    server: {
      hostname: require('os').hostname(),
      pid: process.pid,
      memory: process.memoryUsage(),
      uptime: process.uptime()
    }
  };
  
  // Console logging with colors
  const colors = {
    error: '\x1b[31m', // Red
    warn: '\x1b[33m',  // Yellow
    info: '\x1b[36m',  // Cyan
    reset: '\x1b[0m'   // Reset
  };
  
  console.log(`${colors[level]}[${level.toUpperCase()}] ${timestamp} - ID: ${errorId}${colors.reset}`);
  console.log(`${colors[level]}Message: ${error.message}${colors.reset}`);
  
  if (error.statusCode >= 500) {
    console.log(`${colors[level]}Stack: ${error.stack}${colors.reset}`);
  }
  
  // File logging (in production)
  if (process.env.NODE_ENV === 'production') {
    try {
      const logDir = path.join(__dirname, '../logs');
      await fs.mkdir(logDir, { recursive: true });
      
      const logFile = path.join(logDir, `${level}-${new Date().toISOString().split('T')[0]}.log`);
      const logLine = JSON.stringify(logEntry) + '\n';
      
      await fs.appendFile(logFile, logLine);
    } catch (fileError) {
      console.error('Failed to write to log file:', fileError);
    }
  }
  
  return errorId;
};

/**
 * Generate unique error ID
 * @returns {string} Error ID
 */
const generateErrorId = () => {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `ERR_${timestamp}_${random}`.toUpperCase();
};

/**
 * Sanitize request body for logging (remove sensitive data)
 * @param {Object} body - Request body
 * @returns {Object} Sanitized body
 */
const sanitizeRequestBody = (body) => {
  if (!body || typeof body !== 'object') return body;
  
  const sensitiveFields = [
    'password', 'confirmPassword', 'token', 'secret', 
    'apiKey', 'auth', 'authorization', 'creditCard',
    'ssn', 'socialSecurityNumber', 'bankAccount'
  ];
  
  const sanitized = { ...body };
  
  const sanitizeObject = (obj) => {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (sensitiveFields.some(field => key.toLowerCase().includes(field.toLowerCase()))) {
          obj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      }
    }
  };
  
  sanitizeObject(sanitized);
  return sanitized;
};

// ================================================================
// ERROR RESPONSE FORMATTING
// ================================================================

/**
 * Format error response for client
 * @param {Error} error - Error object
 * @param {Object} req - Express request object
 * @returns {Object} Formatted error response
 */
const formatErrorResponse = (error, req) => {
  const isDevelopment = process.env.NODE_ENV === 'development';
  const errorId = error.errorId || generateErrorId();
  
  // Base error response
  const response = {
    success: false,
    error: error.message || 'An error occurred',
    errorType: error.errorType || ERROR_TYPES.INTERNAL_ERROR,
    errorId,
    timestamp: new Date().toISOString()
  };
  
  // Add details for validation errors
  if (error.errorType === ERROR_TYPES.VALIDATION_ERROR && error.details) {
    response.validationErrors = error.details;
  }
  
  // Add stack trace in development
  if (isDevelopment && error.stack) {
    response.stack = error.stack;
    response.details = error.details;
  }
  
  // Add helpful messages for common errors
  switch (error.statusCode) {
    case HTTP_STATUS_CODES.UNAUTHORIZED:
      response.message = 'Authentication required. Please log in.';
      break;
    case HTTP_STATUS_CODES.FORBIDDEN:
      response.message = 'You don\'t have permission to access this resource.';
      break;
    case HTTP_STATUS_CODES.NOT_FOUND:
      response.message = 'The requested resource was not found.';
      break;
    case HTTP_STATUS_CODES.TOO_MANY_REQUESTS:
      response.message = 'Too many requests. Please try again later.';
      response.retryAfter = error.retryAfter || '15 minutes';
      break;
    case HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR:
      response.message = 'An internal server error occurred. Please try again later.';
      response.supportContact = process.env.SUPPORT_EMAIL || 'support@example.com';
      break;
  }
  
  return response;
};

// ================================================================
// DATABASE ERROR HANDLING
// ================================================================

/**
 * Handle database-specific errors
 * @param {Error} error - Database error
 * @returns {AppError} Processed error
 */
const handleDatabaseError = (error) => {
  // MySQL error codes
  switch (error.code) {
    case 'ER_DUP_ENTRY':
      const field = extractDuplicateField(error.message);
      return new DuplicateError(
        `${field} already exists`,
        { field, originalError: error.sqlMessage }
      );
      
    case 'ER_NO_REFERENCED_ROW_2':
      return new ValidationError(
        'Referenced record does not exist',
        { originalError: error.sqlMessage }
      );
      
    case 'ER_ROW_IS_REFERENCED_2':
      return new ValidationError(
        'Cannot delete record as it is being used elsewhere',
        { originalError: error.sqlMessage }
      );
      
    case 'ER_DATA_TOO_LONG':
      return new ValidationError(
        'Data is too long for the field',
        { originalError: error.sqlMessage }
      );
      
    case 'ER_BAD_NULL_ERROR':
      const nullField = extractNullField(error.message);
      return new ValidationError(
        `${nullField} is required`,
        { field: nullField, originalError: error.sqlMessage }
      );
      
    case 'ER_NO_SUCH_TABLE':
      return new DatabaseError(
        'Database table not found',
        { originalError: error.sqlMessage }
      );
      
    case 'ECONNREFUSED':
      return new DatabaseError(
        'Unable to connect to database',
        { originalError: error.message }
      );
      
    case 'ER_ACCESS_DENIED_ERROR':
      return new DatabaseError(
        'Database access denied',
        { originalError: error.sqlMessage }
      );
      
    default:
      return new DatabaseError(
        'Database operation failed',
        { 
          code: error.code,
          errno: error.errno,
          originalError: error.sqlMessage || error.message 
        }
      );
  }
};

/**
 * Extract duplicate field from MySQL error message
 * @param {string} message - Error message
 * @returns {string} Field name
 */
const extractDuplicateField = (message) => {
  const match = message.match(/key '([^']+)'/);
  if (match) {
    const keyName = match[1];
    // Convert idx_users_email to email
    const fieldMatch = keyName.match(/([^_]+)$/);
    return fieldMatch ? fieldMatch[1] : keyName;
  }
  return 'field';
};

/**
 * Extract null field from MySQL error message
 * @param {string} message - Error message
 * @returns {string} Field name
 */
const extractNullField = (message) => {
  const match = message.match(/Column '([^']+)'/);
  return match ? match[1] : 'field';
};

// ================================================================
// MAIN ERROR HANDLER MIDDLEWARE
// ================================================================

/**
 * Global error handling middleware
 * @param {Error} error - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
const errorHandler = async (error, req, res, next) => {
  try {
    let processedError = error;
    
    // Handle specific error types
    if (error.code && error.code.startsWith('ER_')) {
      processedError = handleDatabaseError(error);
    } else if (error.name === 'ValidationError') {
      processedError = new ValidationError(error.message, error.details);
    } else if (error.name === 'CastError') {
      processedError = new ValidationError('Invalid data format');
    } else if (error.name === 'MulterError') {
      processedError = new FileUploadError(error.message);
    } else if (!error.isOperational) {
      // Convert non-operational errors to operational errors
      processedError = new AppError(
        error.message || 'An unexpected error occurred',
        error.statusCode || HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR,
        ERROR_TYPES.INTERNAL_ERROR
      );
    }
    
    // Log the error
    const errorId = await logError(processedError, req, 
      processedError.statusCode >= 500 ? 'error' : 'warn');
    processedError.errorId = errorId;
    
    // Send error response
    const statusCode = processedError.statusCode || HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR;
    const response = formatErrorResponse(processedError, req);
    
    res.status(statusCode).json(response);
    
  } catch (handlingError) {
    // Fallback error handling
    console.error('Error in error handler:', handlingError);
    
    res.status(HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: 'An unexpected error occurred',
      errorType: ERROR_TYPES.INTERNAL_ERROR,
      errorId: generateErrorId(),
      timestamp: new Date().toISOString()
    });
  }
};

// ================================================================
// ASYNC ERROR WRAPPER
// ================================================================

/**
 * Wrapper for async route handlers to catch errors
 * @param {Function} fn - Async function
 * @returns {Function} Wrapped function
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Main error handler
  errorHandler,
  
  // Error classes
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  DuplicateError,
  DatabaseError,
  ExternalServiceError,
  FileUploadError,
  RateLimitError,
  
  // Utilities
  asyncHandler,
  logError,
  formatErrorResponse,
  handleDatabaseError,
  
  // Constants
  ERROR_TYPES,
  HTTP_STATUS_CODES
};