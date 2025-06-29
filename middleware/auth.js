// ================================================================
// BACKEND/MIDDLEWARE/AUTH.JS - COMPLETE AUTHENTICATION MIDDLEWARE
// Matches the actual database schema with all required functionality
// ================================================================

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { executeQuery, handleDatabaseError } = require('../database/connection');
const { 
  AuthenticationError, 
  AuthorizationError, 
  ValidationError,
  NotFoundError 
} = require('./errorHandler');

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
// PASSWORD UTILITIES
// ================================================================

/**
 * Hash password with bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Hashed password
 */
const hashPassword = async (password) => {
  try {
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
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
 * Generate token pair (access + refresh)
 * @param {Object} user - User object
 * @returns {Object} Token pair
 */
const generateTokenPair = (user) => {
  try {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    
    return {
      accessToken,
      refreshToken,
      accessTokenExpiry: JWT_CONFIG.accessTokenExpiry,
      refreshTokenExpiry: JWT_CONFIG.refreshTokenExpiry,
      tokenType: 'Bearer'
    };
  } catch (error) {
    throw new Error(`Token pair generation failed: ${error.message}`);
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

// ================================================================
// TOKEN REFRESH FUNCTION
// ================================================================

/**
 * Refresh access token using refresh token
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} New token pair
 */
const refreshAccessToken = async (refreshToken) => {
  try {
    const decoded = verifyRefreshToken(refreshToken);
    
    // Get fresh user data from database
    const [users] = await executeQuery(`
      SELECT id, uuid, name, email, user_type, status, 
             email_verified_at, phone_verified_at, 
             is_buyer, is_seller, token_version
      FROM users 
      WHERE id = ? AND status IN ('active', 'pending_verification')
    `, [decoded.id]);
    
    if (users.length === 0) {
      throw new AuthenticationError('User not found or inactive');
    }
    
    const user = users[0];
    
    // Check token version for security (optional - if implemented)
    if (user.token_version && decoded.token_version !== user.token_version) {
      throw new AuthenticationError('Token revoked');
    }
    
    // Generate new token pair
    return generateTokenPair(user);
    
  } catch (error) {
    throw new AuthenticationError(`Token refresh failed: ${error.message}`);
  }
};

// ================================================================
// MAIN AUTHENTICATION MIDDLEWARE
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
      throw new AuthenticationError('Access token required');
    }
    
    // Verify token
    const decoded = verifyAccessToken(token);
    
    // Get fresh user data from database
    const [users] = await executeQuery(`
      SELECT id, uuid, name, email, phone, user_type, status, 
             email_verified_at, phone_verified_at, last_login_at, 
             is_buyer, is_seller, preferred_agent_id,
             login_attempts, locked_until, profile_image,
             license_number, agency_name, agent_rating
      FROM users 
      WHERE id = ? AND status IN ('active', 'pending_verification')
    `, [decoded.id]);
    
    if (users.length === 0) {
      throw new AuthenticationError('User not found or inactive');
    }
    
    const user = users[0];
    
    // Check if user account is suspended
    if (user.status === 'suspended') {
      throw new AuthorizationError('Account suspended');
    }
    
    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AuthenticationError('Account locked due to failed login attempts');
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
      
      const [users] = await executeQuery(`
        SELECT id, uuid, name, email, user_type, status, 
               email_verified_at, phone_verified_at, 
               is_buyer, is_seller, profile_image
        FROM users 
        WHERE id = ? AND status IN ('active', 'pending_verification')
      `, [decoded.id]);
      
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
  
  // Rate limiting helpers
  getUserIdentifier,
  
  // Configuration
  JWT_CONFIG
};

// ================================================================
// USAGE EXAMPLES
// ================================================================

/*
// Basic authentication
router.get('/profile', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Role-based access
router.get('/admin/users', authenticateToken, requireAdmin, (req, res) => {
  // Only admins can access
});

// Property ownership check
router.put('/properties/:id', 
  authenticateToken, 
  requirePropertyOwnership, 
  (req, res) => {
    // Only property owner or admin can update
  }
);

// Agent assignment check
router.get('/agent/clients/:userId', 
  authenticateToken, 
  requireAgentAssignment, 
  (req, res) => {
    // Only assigned agent or admin can access client data
  }
);

// Multiple middleware
router.post('/properties', 
  authenticateToken, 
  requireEmailVerified, 
  requireActiveAccount, 
  (req, res) => {
    // Must be authenticated, email verified, and account active
  }
);

// Optional authentication (for public endpoints with user-specific features)
router.get('/properties', optionalAuth, (req, res) => {
  if (req.user) {
    // Show user-specific data like favorites
  } else {
    // Show general public data
  }
});
*/