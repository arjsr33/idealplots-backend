// ================================================================
// BACKEND/MIDDLEWARE/AUTH.JS - AUTHENTICATION MIDDLEWARE
// FIXED: Now matches the actual database schema from paste.txt
// ================================================================

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { executeQuery, handleDatabaseError } = require('../database/connection');

// ================================================================
// JWT CONFIGURATION
// ================================================================

const JWT_CONFIG = {
  secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
  refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key',
  accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
  refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  issuer: process.env.JWT_ISSUER || 'ideal-plots',
  audience: process.env.JWT_AUDIENCE || 'ideal-plots-users'
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
      is_seller: payload.is_seller
    },
    JWT_CONFIG.secret,
    {
      expiresIn: JWT_CONFIG.accessTokenExpiry,
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience,
      subject: payload.id.toString()
    }
  );
};

/**
 * Generate refresh token
 * @param {Object} payload - User payload
 * @returns {string} JWT refresh token
 */
const generateRefreshToken = (payload) => {
  return jwt.sign(
    {
      id: payload.id,
      uuid: payload.uuid,
      email: payload.email
    },
    JWT_CONFIG.refreshSecret,
    {
      expiresIn: JWT_CONFIG.refreshTokenExpiry,
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience,
      subject: payload.id.toString()
    }
  );
};

/**
 * Generate token pair (access + refresh)
 * @param {Object} user - User object
 * @returns {Object} Token pair
 */
const generateTokenPair = (user) => {
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  
  return {
    accessToken,
    refreshToken,
    accessTokenExpiry: JWT_CONFIG.accessTokenExpiry,
    refreshTokenExpiry: JWT_CONFIG.refreshTokenExpiry
  };
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
    throw new Error(`Invalid access token: ${error.message}`);
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
    throw new Error(`Invalid refresh token: ${error.message}`);
  }
};

// ================================================================
// AUTHENTICATION MIDDLEWARE (FIXED FOR SCHEMA)
// ================================================================

/**
 * Main authentication middleware
 * Extracts and verifies JWT token from request headers
 */
const authenticateToken = async (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required',
        code: 'TOKEN_MISSING'
      });
    }
    
    // Verify token
    const decoded = verifyAccessToken(token);
    
    // Get fresh user data from database (USING ACTUAL SCHEMA FIELDS)
    const [users] = await executeQuery(
      `SELECT id, uuid, name, email, user_type, status, 
              email_verified_at, phone_verified_at, last_login_at, 
              is_buyer, is_seller, preferred_agent_id,
              login_attempts, locked_until
       FROM users 
       WHERE id = ? AND status IN ('active', 'pending_verification')`,
      [decoded.id]
    );
    
    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'User not found or inactive',
        code: 'USER_NOT_FOUND'
      });
    }
    
    const user = users[0];
    
    // Check if user account is suspended
    if (user.status === 'suspended') {
      return res.status(403).json({
        success: false,
        error: 'Account suspended',
        code: 'ACCOUNT_SUSPENDED'
      });
    }
    
    // Check if account is locked (USING ACTUAL SCHEMA FIELD)
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(401).json({
        success: false,
        error: 'Account locked due to failed login attempts',
        code: 'ACCOUNT_LOCKED'
      });
    }
    
    // Add user data to request object (USING ACTUAL SCHEMA FIELDS)
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
      last_login_at: user.last_login_at,
      preferred_agent_id: user.preferred_agent_id
    };
    
    // Update last activity (no last_activity_at field in schema, so skip this)
    
    next();
    
  } catch (error) {
    console.error('Authentication error:', error);
    
    // Handle specific JWT errors
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    } else if (error.name === 'NotBeforeError') {
      return res.status(401).json({
        success: false,
        error: 'Token not active yet',
        code: 'TOKEN_NOT_ACTIVE'
      });
    }
    
    return res.status(500).json({
      success: false,
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
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
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    if (!requiredRoles.includes(req.user.user_type)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Required role: ${requiredRoles.join(' or ')}`,
        code: 'INSUFFICIENT_PERMISSIONS'
      });
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
 * Require user role (regular user)
 */
const requireUser = requireRole('user');

/**
 * Require agent or admin role
 */
const requireAgentOrAdmin = requireRole(['agent', 'admin']);

/**
 * Require verified email (USING ACTUAL SCHEMA FIELD)
 */
const requireEmailVerified = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }
  
  if (!req.user.email_verified) {
    return res.status(403).json({
      success: false,
      error: 'Email verification required',
      code: 'EMAIL_NOT_VERIFIED'
    });
  }
  
  next();
};

/**
 * Require verified phone (USING ACTUAL SCHEMA FIELD)
 */
const requirePhoneVerified = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }
  
  if (!req.user.phone_verified) {
    return res.status(403).json({
      success: false,
      error: 'Phone verification required',
      code: 'PHONE_NOT_VERIFIED'
    });
  }
  
  next();
};

/**
 * Require full verification (email + phone)
 */
const requireFullyVerified = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }
  
  if (!req.user.email_verified || !req.user.phone_verified) {
    return res.status(403).json({
      success: false,
      error: 'Full account verification required',
      code: 'ACCOUNT_NOT_FULLY_VERIFIED'
    });
  }
  
  next();
};

/**
 * Optional authentication - sets req.user if token is valid, continues if not
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return next(); // No token, continue without authentication
    }
    
    const decoded = verifyAccessToken(token);
    
    const [users] = await executeQuery(
      `SELECT id, uuid, name, email, user_type, status, email_verified_at, phone_verified_at,
              is_buyer, is_seller
       FROM users 
       WHERE id = ? AND status IN ('active', 'pending_verification')`,
      [decoded.id]
    );
    
    if (users.length > 0) {
      const user = users[0];
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
        is_seller: user.is_seller
      };
    }
    
    next();
    
  } catch (error) {
    // Invalid token, continue without authentication
    next();
  }
};

// ================================================================
// RESOURCE OWNERSHIP MIDDLEWARE
// ================================================================

/**
 * Check if user owns the resource or is an admin
 * @param {string} resourceIdParam - Parameter name containing resource ID
 * @param {string} table - Database table name
 * @param {string} ownerField - Field name that contains the owner ID
 * @returns {Function} Middleware function
 */
const requireOwnershipOrAdmin = (resourceIdParam, table, ownerField = 'user_id') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }
      
      // Admins can access any resource
      if (req.user.user_type === 'admin') {
        return next();
      }
      
      const resourceId = req.params[resourceIdParam];
      if (!resourceId) {
        return res.status(400).json({
          success: false,
          error: 'Resource ID required',
          code: 'RESOURCE_ID_MISSING'
        });
      }
      
      // Check ownership
      const [resources] = await executeQuery(
        `SELECT ${ownerField} FROM ${table} WHERE id = ?`,
        [resourceId]
      );
      
      if (resources.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Resource not found',
          code: 'RESOURCE_NOT_FOUND'
        });
      }
      
      if (resources[0][ownerField] !== req.user.id) {
        return res.status(403).json({
          success: false,
          error: 'Access denied - not the owner',
          code: 'NOT_OWNER'
        });
      }
      
      next();
      
    } catch (error) {
      console.error('Ownership check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to verify ownership',
        code: 'OWNERSHIP_CHECK_ERROR'
      });
    }
  };
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
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  return await bcrypt.hash(password, saltRounds);
};

/**
 * Compare password with hash
 * @param {string} password - Plain text password
 * @param {string} hash - Hashed password
 * @returns {Promise<boolean>} Password match result
 */
const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

/**
 * Generate secure random password
 * @param {number} length - Password length
 * @returns {string} Generated password
 */
const generateSecurePassword = (length = 12) => {
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
// TOKEN MANAGEMENT UTILITIES
// ================================================================

/**
 * Generate verification token
 * @returns {string} Verification token
 */
const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
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

/**
 * Refresh access token using refresh token
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} New token pair
 */
const refreshAccessToken = async (refreshToken) => {
  try {
    const decoded = verifyRefreshToken(refreshToken);
    
    // Get fresh user data (USING ACTUAL SCHEMA FIELDS)
    const [users] = await executeQuery(
      `SELECT id, uuid, name, email, user_type, status, email_verified_at, phone_verified_at,
              is_buyer, is_seller
       FROM users 
       WHERE id = ? AND status IN ('active', 'pending_verification')`,
      [decoded.id]
    );
    
    if (users.length === 0) {
      throw new Error('User not found or inactive');
    }
    
    const user = users[0];
    
    // Generate new token pair
    return generateTokenPair(user);
    
  } catch (error) {
    throw new Error(`Token refresh failed: ${error.message}`);
  }
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
  
  // Configuration
  JWT_CONFIG
};