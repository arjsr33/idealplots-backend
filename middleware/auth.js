// ================================================================
// BACKEND/MIDDLEWARE/AUTH.JS - ENHANCED AUTHENTICATION MIDDLEWARE
// Complete implementation with security improvements and production hardening
// ================================================================

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { executeQuery, handleDatabaseError } = require('../database/connection');
const { 
  AuthenticationError, 
  AuthorizationError, 
  ValidationError,
  NotFoundError 
} = require('./errorHandler');

// ================================================================
// CONSTANTS
// ================================================================

const CONSTANTS = {
  BCRYPT_ROUNDS: 12,
  TOKEN_BYTES: 32,
  DEFAULT_PASSWORD_LENGTH: 12,
  MAX_LOGIN_ATTEMPTS: 5,
  ACCOUNT_LOCK_DURATION: 30 * 60 * 1000, // 30 minutes
  RATE_LIMIT: {
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MAX_REQUESTS: 100,
    AUTH_MAX: 5,
    VERIFICATION_MAX: 3,
    PASSWORD_RESET_MAX: 3
  }
};

// ================================================================
// JWT CONFIGURATION WITH PRODUCTION SECURITY
// ================================================================

const JWT_CONFIG = {
  secret: (() => {
    if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET must be set in production environment');
    }
    return process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
  })(),
  
  refreshSecret: (() => {
    if (process.env.NODE_ENV === 'production' && !process.env.JWT_REFRESH_SECRET) {
      throw new Error('JWT_REFRESH_SECRET must be set in production environment');
    }
    return process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-key';
  })(),
  
  accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
  refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  issuer: process.env.JWT_ISSUER || 'ideal-plots',
  audience: process.env.JWT_AUDIENCE || 'ideal-plots-users'
};

// ================================================================
// DATABASE UTILITIES
// ================================================================

/**
 * Get user by ID with specified fields
 * @param {number} userId - User ID
 * @param {string} fields - SQL field selection
 * @returns {Promise<Object|null>} User object or null
 */
const getUserById = async (userId, fields = '*') => {
  try {
    const [users] = await executeQuery(
      `SELECT ${fields} FROM users WHERE id = ? AND status IN ('active', 'pending_verification')`,
      [userId]
    );
    return users[0] || null;
  } catch (error) {
    throw new Error(`Failed to fetch user: ${error.message}`);
  }
};

/**
 * Update user token version (for token revocation)
 * @param {number} userId - User ID
 * @returns {Promise<void>}
 */
const incrementTokenVersion = async (userId) => {
  try {
    await executeQuery(
      'UPDATE users SET token_version = COALESCE(token_version, 0) + 1, updated_at = NOW() WHERE id = ?',
      [userId]
    );
  } catch (error) {
    throw new Error(`Failed to increment token version: ${error.message}`);
  }
};

// ================================================================
// PASSWORD UTILITIES
// ================================================================

/**
 * Hash password with bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Hashed password
 */
const hashPassword = async (password) => {
  try {
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || CONSTANTS.BCRYPT_ROUNDS;
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    throw new Error(`Password hashing failed: ${error.message}`);
  }
};

/**
 * Compare password with hash
 * @param {string} password - Plain text password
 * @param {string} hash - Hashed password
 * @returns {Promise<boolean>} Password match result
 */
const comparePassword = async (password, hash) => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    throw new Error(`Password comparison failed: ${error.message}`);
  }
};

/**
 * Generate secure random password
 * @param {number} length - Password length
 * @returns {string} Generated password
 */
const generateSecurePassword = (length = CONSTANTS.DEFAULT_PASSWORD_LENGTH) => {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let password = '';
  
  // Ensure at least one of each character type
  password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
  password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
  password += '0123456789'[Math.floor(Math.random() * 10)];
  password += '!@#$%^&*'[Math.floor(Math.random() * 8)];
  
  // Fill remaining length
  for (let i = 4; i < length; i++) {
    password += charset[Math.floor(Math.random() * charset.length)];
  }
  
  // Shuffle password
  return password.split('').sort(() => Math.random() - 0.5).join('');
};

// ================================================================
// TOKEN GENERATION FUNCTIONS
// ================================================================

/**
 * Generate access token
 * @param {Object} payload - User payload
 * @returns {string} JWT access token
 */
const generateAccessToken = (payload) => {
  try {
    return jwt.sign(
      {
        id: payload.id,
        uuid: payload.uuid,
        email: payload.email,
        user_type: payload.user_type,
        status: payload.status,
        email_verified: !!payload.email_verified_at,
        phone_verified: !!payload.phone_verified_at,
        is_buyer: payload.is_buyer,
        is_seller: payload.is_seller,
        iat: Math.floor(Date.now() / 1000)
      },
      JWT_CONFIG.secret,
      {
        expiresIn: JWT_CONFIG.accessTokenExpiry,
        issuer: JWT_CONFIG.issuer,
        audience: JWT_CONFIG.audience,
        subject: payload.id.toString()
      }
    );
  } catch (error) {
    throw new Error(`Access token generation failed: ${error.message}`);
  }
};

/**
 * Generate refresh token
 * @param {Object} payload - User payload
 * @returns {string} JWT refresh token
 */
const generateRefreshToken = (payload) => {
  try {
    return jwt.sign(
      {
        id: payload.id,
        uuid: payload.uuid,
        email: payload.email,
        token_version: payload.token_version || 1,
        iat: Math.floor(Date.now() / 1000)
      },
      JWT_CONFIG.refreshSecret,
      {
        expiresIn: JWT_CONFIG.refreshTokenExpiry,
        issuer: JWT_CONFIG.issuer,
        audience: JWT_CONFIG.audience,
        subject: payload.id.toString()
      }
    );
  } catch (error) {
    throw new Error(`Refresh token generation failed: ${error.message}`);
  }
};

/**
 * Generate token pair (access + refresh) with expiry timestamps
 * @param {Object} user - User object
 * @returns {Object} Token pair with metadata
 */
const generateTokenPair = (user) => {
  try {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    
    // Calculate actual expiry timestamps
    const now = Date.now();
    const accessTokenExpiryMs = parseExpiry(JWT_CONFIG.accessTokenExpiry);
    const refreshTokenExpiryMs = parseExpiry(JWT_CONFIG.refreshTokenExpiry);
    
    return {
      accessToken,
      refreshToken,
      accessTokenExpiry: JWT_CONFIG.accessTokenExpiry,
      refreshTokenExpiry: JWT_CONFIG.refreshTokenExpiry,
      accessTokenExpiresAt: new Date(now + accessTokenExpiryMs).toISOString(),
      refreshTokenExpiresAt: new Date(now + refreshTokenExpiryMs).toISOString(),
      tokenType: 'Bearer'
    };
  } catch (error) {
    throw new Error(`Token pair generation failed: ${error.message}`);
  }
};

/**
 * Parse JWT expiry string to milliseconds
 * @param {string} expiry - Expiry string (e.g., '15m', '7d')
 * @returns {number} Expiry in milliseconds
 */
const parseExpiry = (expiry) => {
  const unit = expiry.slice(-1);
  const value = parseInt(expiry.slice(0, -1));
  
  switch (unit) {
    case 's': return value * 1000;
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default: return 15 * 60 * 1000; // Default to 15 minutes
  }
};

// ================================================================
// TOKEN VERIFICATION FUNCTIONS
// ================================================================

/**
 * Verify access token
 * @param {string} token - JWT token
 * @returns {Object} Decoded token payload
 */
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, JWT_CONFIG.secret, {
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience
    });
  } catch (error) {
    throw new AuthenticationError(`Invalid access token: ${error.message}`);
  }
};

/**
 * Verify refresh token
 * @param {string} token - JWT refresh token
 * @returns {Object} Decoded token payload
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, JWT_CONFIG.refreshSecret, {
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience
    });
  } catch (error) {
    throw new AuthenticationError(`Invalid refresh token: ${error.message}`);
  }
};

// ================================================================
// VERIFICATION UTILITIES
// ================================================================

/**
 * Generate verification token
 * @returns {string} Verification token
 */
const generateVerificationToken = () => {
  return crypto.randomBytes(CONSTANTS.TOKEN_BYTES).toString('hex');
};

/**
 * Generate verification code (numeric)
 * @param {number} length - Code length
 * @returns {string} Verification code
 */
const generateVerificationCode = (length = 6) => {
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length) - 1;
  return Math.floor(Math.random() * (max - min + 1) + min).toString();
};

// ================================================================
// TOKEN REFRESH FUNCTION WITH ROTATION
// ================================================================

/**
 * Refresh access token using refresh token with token rotation
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} New token pair
 */
const refreshAccessToken = async (refreshToken) => {
  try {
    const decoded = verifyRefreshToken(refreshToken);
    
    // Invalidate old refresh token by incrementing token version
    await incrementTokenVersion(decoded.id);
    
    // Get fresh user data with new token_version
    const user = await getUserById(decoded.id, `
      id, uuid, name, email, user_type, status, 
      email_verified_at, phone_verified_at, 
      is_buyer, is_seller, token_version
    `);
    
    if (!user) {
      throw new AuthenticationError('User not found or inactive');
    }
    
    // Check token version for security (token revocation)
    if (user.token_version && decoded.token_version !== user.token_version - 1) {
      throw new AuthenticationError('Token revoked - please login again');
    }
    
    // Generate new token pair with updated token version
    return generateTokenPair(user);
    
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    throw new AuthenticationError(`Token refresh failed: ${error.message}`);
  }
};

// ================================================================
// RATE LIMITING CONFIGURATION
// ================================================================

const RATE_LIMIT_CONFIG = {
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || CONSTANTS.RATE_LIMIT.WINDOW_MS,
  max: parseInt(process.env.RATE_LIMIT_MAX) || CONSTANTS.RATE_LIMIT.MAX_REQUESTS,
  message: {
    error: 'Too many requests',
    message: 'Rate limit exceeded. Please try again later.',
    retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW) || CONSTANTS.RATE_LIMIT.WINDOW_MS) / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getUserIdentifier(req),
  handler: (req, res) => {
    res.status(429).json(RATE_LIMIT_CONFIG.message);
  }
};

// ================================================================
// RATE LIMITING MIDDLEWARE
// ================================================================

/**
 * General rate limiting middleware
 */
const rateLimiter = rateLimit(RATE_LIMIT_CONFIG);

/**
 * Strict rate limiting for authentication endpoints
 */
const authRateLimiter = rateLimit({
  ...RATE_LIMIT_CONFIG,
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: CONSTANTS.RATE_LIMIT.AUTH_MAX,
  message: {
    error: 'Too many authentication attempts',
    message: 'Too many login attempts. Please try again in 15 minutes.',
    retryAfter: 900
  }
});

/**
 * Password reset rate limiting
 */
const passwordResetRateLimiter = rateLimit({
  ...RATE_LIMIT_CONFIG,
  windowMs: 60 * 60 * 1000, // 1 hour
  max: CONSTANTS.RATE_LIMIT.PASSWORD_RESET_MAX,
  message: {
    error: 'Too many password reset attempts',
    message: 'Too many password reset requests. Please try again in 1 hour.',
    retryAfter: 3600
  }
});

/**
 * Email verification rate limiting
 */
const emailVerificationRateLimiter = rateLimit({
  ...RATE_LIMIT_CONFIG,
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: CONSTANTS.RATE_LIMIT.VERIFICATION_MAX,
  message: {
    error: 'Too many verification requests',
    message: 'Too many verification emails sent. Please wait 5 minutes.',
    retryAfter: 300
  }
});

// ================================================================
// MAIN AUTHENTICATION MIDDLEWARE
// ================================================================

/**
 * Main authentication middleware with enhanced security
 * Extracts and verifies JWT token from request headers
 */
const authenticateToken = async (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      throw new AuthenticationError('Access token required');
    }
    
    // Verify token
    const decoded = verifyAccessToken(token);
    
    // Get fresh user data from database
    const user = await getUserById(decoded.id, `
      id, uuid, name, email, phone, user_type, status, 
      email_verified_at, phone_verified_at, last_login_at, 
      is_buyer, is_seller, preferred_agent_id,
      login_attempts, locked_until, profile_image,
      license_number, agency_name, agent_rating, token_version
    `);
    
    if (!user) {
      throw new AuthenticationError('User not found or inactive');
    }
    
    // Check if user account is suspended
    if (user.status === 'suspended') {
      throw new AuthorizationError('Account suspended');
    }
    
    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AuthenticationError('Account locked due to failed login attempts');
    }
    
    // Check token version for revocation (if implemented)
    if (user.token_version && decoded.token_version && decoded.token_version < user.token_version) {
      throw new AuthenticationError('Token revoked - please login again');
    }
    
    // Add user data to request object
    req.user = {
      id: user.id,
      uuid: user.uuid,
      name: user.name,
      email: user.email,
      phone: user.phone,
      user_type: user.user_type,
      status: user.status,
      email_verified: !!user.email_verified_at,
      phone_verified: !!user.phone_verified_at,
      is_buyer: user.is_buyer,
      is_seller: user.is_seller,
      last_login_at: user.last_login_at,
      preferred_agent_id: user.preferred_agent_id,
      profile_image: user.profile_image,
      // Agent specific fields
      license_number: user.license_number,
      agency_name: user.agency_name,
      agent_rating: user.agent_rating
    };
    
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication middleware
 * Allows access without token but adds user data if token is provided
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      req.user = null;
      return next();
    }
    
    // Try to authenticate, but don't fail if token is invalid
    try {
      const decoded = verifyAccessToken(token);
      
      const user = await getUserById(decoded.id, `
        id, uuid, name, email, user_type, status, 
        email_verified_at, phone_verified_at, 
        is_buyer, is_seller, profile_image
      `);
      
      if (user) {
        req.user = {
          id: user.id,
          uuid: user.uuid,
          name: user.name,
          email: user.email,
          user_type: user.user_type,
          status: user.status,
          email_verified: !!user.email_verified_at,
          phone_verified: !!user.phone_verified_at,
          is_buyer: user.is_buyer,
          is_seller: user.is_seller,
          profile_image: user.profile_image
        };
      } else {
        req.user = null;
      }
    } catch (error) {
      req.user = null;
    }
    
    next();
  } catch (error) {
    req.user = null;
    next();
  }
};

// ================================================================
// ROLE-BASED ACCESS CONTROL MIDDLEWARE
// ================================================================

/**
 * Require specific user role
 * @param {string|Array} roles - Required role(s)
 * @returns {Function} Middleware function
 */
const requireRole = (roles) => {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];
  
  return (req, res, next) => {
    if (!req.user) {
      return next(new AuthenticationError('Authentication required'));
    }
    
    if (!requiredRoles.includes(req.user.user_type)) {
      return next(new AuthorizationError(
        `Access denied. Required role(s): ${requiredRoles.join(', ')}`
      ));
    }
    
    next();
  };
};

/**
 * Require admin role
 */
const requireAdmin = requireRole('admin');

/**
 * Require agent role
 */
const requireAgent = requireRole('agent');

/**
 * Require user role
 */
const requireUser = requireRole('user');

/**
 * Require agent or admin role
 */
const requireAgentOrAdmin = requireRole(['agent', 'admin']);

// ================================================================
// VERIFICATION REQUIREMENTS MIDDLEWARE
// ================================================================

/**
 * Require email verification
 */
const requireEmailVerified = (req, res, next) => {
  if (!req.user) {
    return next(new AuthenticationError('Authentication required'));
  }
  
  if (!req.user.email_verified) {
    return next(new AuthorizationError('Email verification required'));
  }
  
  next();
};

/**
 * Require phone verification
 */
const requirePhoneVerified = (req, res, next) => {
  if (!req.user) {
    return next(new AuthenticationError('Authentication required'));
  }
  
  if (!req.user.phone_verified) {
    return next(new AuthorizationError('Phone verification required'));
  }
  
  next();
};

/**
 * Require both email and phone verification
 */
const requireFullyVerified = (req, res, next) => {
  if (!req.user) {
    return next(new AuthenticationError('Authentication required'));
  }
  
  if (!req.user.email_verified || !req.user.phone_verified) {
    return next(new AuthorizationError('Account verification required'));
  }
  
  next();
};

// ================================================================
// RESOURCE OWNERSHIP MIDDLEWARE
// ================================================================

/**
 * Require resource ownership or admin access
 * @param {string} resourceIdParam - Parameter name for resource ID
 * @param {string} resourceTable - Database table name
 * @param {string} ownerColumn - Column name for owner ID
 * @returns {Function} Middleware function
 */
const requireOwnershipOrAdmin = (resourceIdParam = 'id', resourceTable, ownerColumn = 'owner_id') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next(new AuthenticationError('Authentication required'));
      }
      
      // Admin can access everything
      if (req.user.user_type === 'admin') {
        return next();
      }
      
      const resourceId = req.params[resourceIdParam];
      
      if (!resourceId) {
        return next(new ValidationError(`Resource ID parameter '${resourceIdParam}' is required`));
      }
      
      if (!resourceTable) {
        return next(new Error('Resource table not specified for ownership check'));
      }
      
      // Check ownership
      const [resources] = await executeQuery(
        `SELECT ${ownerColumn} FROM ${resourceTable} WHERE id = ?`,
        [resourceId]
      );
      
      if (resources.length === 0) {
        return next(new NotFoundError('Resource not found'));
      }
      
      const ownerId = resources[0][ownerColumn];
      
      if (ownerId !== req.user.id) {
        return next(new AuthorizationError('Access denied. You can only access your own resources.'));
      }
      
      next();
      
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Require property ownership or admin access
 */
const requirePropertyOwnership = requireOwnershipOrAdmin('id', 'property_listings', 'owner_id');

/**
 * Require user profile ownership or admin access
 */
const requireProfileOwnership = (req, res, next) => {
  if (!req.user) {
    return next(new AuthenticationError('Authentication required'));
  }
  
  // Admin can access any profile
  if (req.user.user_type === 'admin') {
    return next();
  }
  
  const targetUserId = req.params.id || req.params.userId;
  
  if (!targetUserId) {
    return next(new ValidationError('User ID parameter is required'));
  }
  
  // User can only access their own profile
  if (parseInt(targetUserId) !== req.user.id) {
    return next(new AuthorizationError('Access denied. You can only access your own profile.'));
  }
  
  next();
};

// ================================================================
// AGENT SPECIFIC MIDDLEWARE
// ================================================================

/**
 * Require agent assignment or admin access
 * Checks if the agent is assigned to handle the user/property
 */
const requireAgentAssignment = async (req, res, next) => {
  try {
    if (!req.user) {
      return next(new AuthenticationError('Authentication required'));
    }
    
    // Admin can access everything
    if (req.user.user_type === 'admin') {
      return next();
    }
    
    // Must be an agent
    if (req.user.user_type !== 'agent') {
      return next(new AuthorizationError('Agent access required'));
    }
    
    const targetUserId = req.params.userId;
    
    if (targetUserId) {
      // Check if agent is assigned to this user
      const [assignments] = await executeQuery(`
        SELECT id FROM user_agent_assignments 
        WHERE user_id = ? AND agent_id = ? AND status = 'active'
      `, [targetUserId, req.user.id]);
      
      if (assignments.length === 0) {
        return next(new AuthorizationError('Agent not assigned to this user'));
      }
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};

// ================================================================
// STATUS CHECK MIDDLEWARE
// ================================================================

/**
 * Ensure user account is active
 */
const requireActiveAccount = (req, res, next) => {
  if (!req.user) {
    return next(new AuthenticationError('Authentication required'));
  }
  
  if (req.user.status !== 'active') {
    const statusMessages = {
      'pending_verification': 'Account verification required',
      'inactive': 'Account is inactive',
      'suspended': 'Account is suspended'
    };
    
    return next(new AuthorizationError(
      statusMessages[req.user.status] || 'Account access denied'
    ));
  }
  
  next();
};

// ================================================================
// RATE LIMITING HELPERS
// ================================================================

/**
 * Extract user identifier for rate limiting
 * @param {Object} req - Express request object
 * @returns {string} User identifier
 */
const getUserIdentifier = (req) => {
  if (req.user && req.user.id) {
    return `user:${req.user.id}`;
  }
  
  // Fall back to IP address
  return `ip:${req.ip || req.connection.remoteAddress}`;
};

// ================================================================
// MIDDLEWARE COMPOSITION HELPERS
// ================================================================

/**
 * Compose multiple middleware functions
 * @param {...Function} middlewares - Middleware functions
 * @returns {Function} Combined middleware function
 */
const composeMiddleware = (...middlewares) => {
  return (req, res, next) => {
    let index = 0;
    
    const runMiddleware = (middlewareIndex) => {
      if (middlewareIndex >= middlewares.length) {
        return next();
      }
      
      const middleware = middlewares[middlewareIndex];
      middleware(req, res, (err) => {
        if (err) {
          return next(err);
        }
        runMiddleware(middlewareIndex + 1);
      });
    };
    
    runMiddleware(0);
  };
};

/**
 * Common middleware combinations
 */
const authMiddleware = {
  // Basic authentication
  basic: authenticateToken,
  
  // Authentication with email verification
  verified: composeMiddleware(authenticateToken, requireEmailVerified),
  
  // Full verification (email + phone)
  fullyVerified: composeMiddleware(authenticateToken, requireFullyVerified),
  
  // Active account with full verification
  activeAndVerified: composeMiddleware(authenticateToken, requireActiveAccount, requireFullyVerified),
  
  // Agent with assignment check
  agentWithAssignment: composeMiddleware(authenticateToken, requireAgent, requireAgentAssignment),
  
  // Admin only
  adminOnly: composeMiddleware(authenticateToken, requireAdmin)
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Main authentication
  authenticateToken,
  optionalAuth,
  
  // Role-based access control
  requireRole,
  requireAdmin,
  requireAgent,
  requireUser,
  requireAgentOrAdmin,
  
  // Verification requirements
  requireEmailVerified,
  requirePhoneVerified,
  requireFullyVerified,
  
  // Resource ownership
  requireOwnershipOrAdmin,
  requirePropertyOwnership,
  requireProfileOwnership,
  
  // Agent specific
  requireAgentAssignment,
  
  // Status checks
  requireActiveAccount,
  
  // Token management
  generateTokenPair,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  refreshAccessToken,
  
  // Password utilities
  hashPassword,
  comparePassword,
  generateSecurePassword,
  
  // Verification utilities
  generateVerificationToken,
  generateVerificationCode,
  
  // Rate limiting
  rateLimiter,
  authRateLimiter,
  passwordResetRateLimiter,
  emailVerificationRateLimiter,
  getUserIdentifier,
  
  // Middleware composition
  composeMiddleware,
  authMiddleware,
  
  // Database utilities
  getUserById,
  incrementTokenVersion,
  
  // Configuration
  JWT_CONFIG,
  CONSTANTS
};
