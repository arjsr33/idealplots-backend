// ================================================================
// BACKEND/ROUTES/AUTH.JS - AUTHENTICATION & REGISTRATION ROUTES
// User registration with role selection, email/phone verification, password reset
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// Import middleware and services
const { 
  authenticateToken, 
  optionalAuth,
  hashPassword, 
  comparePassword,
  generateTokenPair,
  generateVerificationToken,
  generateVerificationCode,
  refreshAccessToken
} = require('../middleware/auth');

const { 
  asyncHandler, 
  ValidationError, 
  AuthenticationError,
  NotFoundError,
  DuplicateError 
} = require('../middleware/errorHandler');

const { executeQuery, executeTransaction, handleDatabaseError } = require('../database/connection');
const notificationService = require('../services/notificationService');

const router = express.Router();

// ================================================================
// RATE LIMITING
// ================================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: {
    success: false,
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const verificationLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // 3 verification attempts per window
  message: {
    success: false,
    error: 'Too many verification attempts, please try again later.',
    retryAfter: '5 minutes'
  }
});

// ================================================================
// VALIDATION RULES
// ================================================================

const registerValidation = [
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
    .withMessage('Valid phone number required (E.164 format)'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be 8+ chars with uppercase, lowercase, number, and special character'),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  
  body('user_type')
    .isIn(['user', 'agent'])
    .withMessage('User type must be either "user" or "agent"'),
  
  // Agent-specific fields (conditional validation)
  body('license_number')
    .if(body('user_type').equals('agent'))
    .isLength({ min: 5, max: 100 })
    .trim()
    .withMessage('License number required for agents (5-100 characters)'),
  
  body('agency_name')
    .if(body('user_type').equals('agent'))
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Agency name required for agents (2-255 characters)'),
  
  body('experience_years')
    .if(body('user_type').equals('agent'))
    .isInt({ min: 0, max: 50 })
    .withMessage('Experience years required for agents (0-50)'),
  
  body('commission_rate')
    .if(body('user_type').equals('agent'))
    .optional()
    .isFloat({ min: 0, max: 99.99 })
    .withMessage('Commission rate must be between 0-99.99'),
  
  body('specialization')
    .if(body('user_type').equals('agent'))
    .optional()
    .isLength({ max: 1000 })
    .trim()
    .withMessage('Specialization must be under 1000 characters'),
  
  body('agent_bio')
    .if(body('user_type').equals('agent'))
    .optional()
    .isLength({ max: 2000 })
    .trim()
    .withMessage('Bio must be under 2000 characters')
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required'),
  
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password required')
];

const passwordResetValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required')
];

const passwordResetConfirmValidation = [
  body('token')
    .isLength({ min: 32 })
    .withMessage('Valid reset token required'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be 8+ chars with uppercase, lowercase, number, and special character'),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
];

// ================================================================
// REGISTRATION ROUTES
// ================================================================

/**
 * User Registration with Role Selection
 * POST /api/auth/register
 */
router.post('/register',
  authLimiter,
  registerValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      name,
      email,
      phone,
      password,
      user_type,
      license_number,
      agency_name,
      experience_years,
      commission_rate,
      specialization,
      agent_bio
    } = req.body;

    const result = await executeTransaction(async (connection) => {
      // Check for existing email
      const [emailExists] = await connection.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );
      
      if (emailExists.length > 0) {
        throw new DuplicateError('Email address already registered');
      }

      // Check for existing phone
      const [phoneExists] = await connection.execute(
        'SELECT id FROM users WHERE phone = ?',
        [phone]
      );
      
      if (phoneExists.length > 0) {
        throw new DuplicateError('Phone number already registered');
      }

      // For agents, check license number uniqueness
      if (user_type === 'agent' && license_number) {
        const [licenseExists] = await connection.execute(
          'SELECT id FROM users WHERE license_number = ?',
          [license_number]
        );
        
        if (licenseExists.length > 0) {
          throw new DuplicateError('License number already registered');
        }
      }

      // Hash password
      const hashedPassword = await hashPassword(password);
      
      // Generate verification tokens
      const emailToken = generateVerificationToken();
      const phoneCode = generateVerificationCode(6);

      // Determine initial status based on user type
      const initialStatus = user_type === 'agent' ? 'pending_approval' : 'pending_verification';

      // Create user account
      const [userResult] = await connection.execute(`
        INSERT INTO users (
          name, email, phone, password, user_type, status,
          email_verification_token, phone_verification_code,
          license_number, agency_name, experience_years, 
          commission_rate, specialization, agent_bio,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `, [
        name, email, phone, hashedPassword, user_type, initialStatus,
        emailToken, phoneCode,
        license_number || null,
        agency_name || null,
        experience_years || null,
        commission_rate || null,
        specialization || null,
        agent_bio || null
      ]);

      const userId = userResult.insertId;

      // If agent registration, create pending approval record
      if (user_type === 'agent') {
        await connection.execute(`
          INSERT INTO pending_approvals (
            user_id, approval_type, submitted_at, status
          ) VALUES (?, 'agent_registration', NOW(), 'pending')
        `, [userId]);
      }

      // Get created user details (excluding password)
      const [newUser] = await connection.execute(`
        SELECT 
          id, name, email, phone, user_type, status, created_at,
          license_number, agency_name, experience_years, commission_rate
        FROM users WHERE id = ?
      `, [userId]);

      const user = newUser[0];

      // Send verification notifications
      const notificationResults = {
        email: { sent: false, error: null },
        sms: { sent: false, error: null }
      };

      // Send email verification
      try {
        await notificationService.sendEmail({
          to: email,
          subject: `Welcome to ${process.env.COMPANY_NAME || 'Real Estate Platform'} - Verify Your Email`,
          html: notificationService.emailTemplates.emailVerification({
            name,
            token: emailToken
          }).html
        });
        notificationResults.email.sent = true;
      } catch (error) {
        notificationResults.email.error = error.message;
      }

      // Send SMS verification
      try {
        await notificationService.sendSMS({
          to: phone,
          body: notificationService.smsTemplates.phoneVerification({ code: phoneCode })
        });
        notificationResults.sms.sent = true;
      } catch (error) {
        notificationResults.sms.error = error.message;
      }

      return {
        user,
        notifications: notificationResults,
        tokens: {
          emailToken,
          phoneCode
        }
      };
    });

    res.status(201).json({
      success: true,
      message: user_type === 'agent' 
        ? 'Agent registration submitted for approval. Please verify your email and phone.'
        : 'Registration successful. Please verify your email and phone.',
      data: {
        user: result.user,
        notifications: result.notifications,
        nextSteps: user_type === 'agent' 
          ? ['verify_email', 'verify_phone', 'await_approval']
          : ['verify_email', 'verify_phone']
      }
    });
  })
);

// ================================================================
// LOGIN ROUTES
// ================================================================

/**
 * User Login
 * POST /api/auth/login
 */
router.post('/login',
  authLimiter,
  loginValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { email, password } = req.body;

    // Get user with password for verification
    const [users] = await executeQuery(`
      SELECT 
        id, name, email, phone, password, user_type, status,
        email_verified_at, phone_verified_at, token_version,
        last_login_at, failed_login_attempts, locked_until
      FROM users 
      WHERE email = ?
    `, [email]);

    if (users.length === 0) {
      throw new AuthenticationError('Invalid email or password');
    }

    const user = users[0];

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AuthenticationError(`Account locked until ${user.locked_until}`);
    }

    // Check if account is active
    if (['suspended', 'deleted'].includes(user.status)) {
      throw new AuthenticationError('Account suspended or deactivated');
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password);
    
    if (!isPasswordValid) {
      // Increment failed login attempts
      const failedAttempts = (user.failed_login_attempts || 0) + 1;
      const lockUntil = failedAttempts >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null; // 30 min lock

      await executeQuery(`
        UPDATE users 
        SET failed_login_attempts = ?, locked_until = ?
        WHERE id = ?
      `, [failedAttempts, lockUntil, user.id]);

      throw new AuthenticationError('Invalid email or password');
    }

    // Reset failed login attempts on successful login
    await executeQuery(`
      UPDATE users 
      SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW()
      WHERE id = ?
    `, [user.id]);

    // Generate JWT tokens
    const tokens = generateTokenPair(user);

    // Remove sensitive data from response
    const { password: _, ...userResponse } = user;
    userResponse.email_verified = !!user.email_verified_at;
    userResponse.phone_verified = !!user.phone_verified_at;

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        tokens
      }
    });
  })
);

/**
 * Refresh Token
 * POST /api/auth/refresh
 */
router.post('/refresh',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new ValidationError('Refresh token required');
    }

    const tokens = await refreshAccessToken(refreshToken);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: { tokens }
    });
  })
);

/**
 * Logout
 * POST /api/auth/logout
 */
router.post('/logout',
  authenticateToken,
  asyncHandler(async (req, res) => {
    // In a production app, you might want to blacklist the token
    // For now, we'll just return success
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  })
);

// ================================================================
// EMAIL VERIFICATION ROUTES
// ================================================================

/**
 * Verify Email
 * POST /api/auth/verify-email
 */
router.post('/verify-email',
  verificationLimiter,
  asyncHandler(async (req, res) => {
    const { token } = req.body;

    if (!token) {
      throw new ValidationError('Verification token required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, email, email_verification_token, email_verified_at
      FROM users 
      WHERE email_verification_token = ? AND email_verified_at IS NULL
    `, [token]);

    if (users.length === 0) {
      throw new ValidationError('Invalid or expired verification token');
    }

    const user = users[0];

    // Mark email as verified
    await executeQuery(`
      UPDATE users 
      SET email_verified_at = NOW(), email_verification_token = NULL, updated_at = NOW()
      WHERE id = ?
    `, [user.id]);

    res.json({
      success: true,
      message: 'Email verified successfully',
      data: {
        email: user.email,
        verified_at: new Date().toISOString()
      }
    });
  })
);

/**
 * Resend Email Verification
 * POST /api/auth/resend-email-verification
 */
router.post('/resend-email-verification',
  verificationLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
      throw new ValidationError('Email address required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, email, email_verified_at
      FROM users 
      WHERE email = ? AND email_verified_at IS NULL
    `, [email]);

    if (users.length === 0) {
      throw new NotFoundError('User not found or email already verified');
    }

    const user = users[0];
    const newToken = generateVerificationToken();

    // Update user with new token
    await executeQuery(`
      UPDATE users 
      SET email_verification_token = ?, updated_at = NOW()
      WHERE id = ?
    `, [newToken, user.id]);

    // Send verification email
    const result = await notificationService.sendVerificationEmail(user.id);

    res.json({
      success: true,
      message: 'Verification email sent successfully',
      data: result
    });
  })
);

// ================================================================
// PHONE VERIFICATION ROUTES
// ================================================================

/**
 * Verify Phone
 * POST /api/auth/verify-phone
 */
router.post('/verify-phone',
  verificationLimiter,
  asyncHandler(async (req, res) => {
    const { phone, code } = req.body;

    if (!phone || !code) {
      throw new ValidationError('Phone number and verification code required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, phone, phone_verification_code, phone_verified_at
      FROM users 
      WHERE phone = ? AND phone_verification_code = ? AND phone_verified_at IS NULL
    `, [phone, code]);

    if (users.length === 0) {
      throw new ValidationError('Invalid verification code or phone already verified');
    }

    const user = users[0];

    // Mark phone as verified
    await executeQuery(`
      UPDATE users 
      SET phone_verified_at = NOW(), phone_verification_code = NULL, updated_at = NOW()
      WHERE id = ?
    `, [user.id]);

    res.json({
      success: true,
      message: 'Phone verified successfully',
      data: {
        phone: user.phone,
        verified_at: new Date().toISOString()
      }
    });
  })
);

/**
 * Resend Phone Verification
 * POST /api/auth/resend-phone-verification
 */
router.post('/resend-phone-verification',
  verificationLimiter,
  asyncHandler(async (req, res) => {
    const { phone } = req.body;

    if (!phone) {
      throw new ValidationError('Phone number required');
    }

    const [users] = await executeQuery(`
      SELECT id, name, phone, phone_verified_at
      FROM users 
      WHERE phone = ? AND phone_verified_at IS NULL
    `, [phone]);

    if (users.length === 0) {
      throw new NotFoundError('User not found or phone already verified');
    }

    const user = users[0];
    const newCode = generateVerificationCode(6);

    // Update user with new code
    await executeQuery(`
      UPDATE users 
      SET phone_verification_code = ?, updated_at = NOW()
      WHERE id = ?
    `, [newCode, user.id]);

    // Send verification SMS
    const result = await notificationService.sendVerificationSMS(user.id);

    res.json({
      success: true,
      message: 'Verification SMS sent successfully',
      data: result
    });
  })
);

// ================================================================
// PASSWORD RESET ROUTES
// ================================================================

/**
 * Request Password Reset
 * POST /api/auth/forgot-password
 */
router.post('/forgot-password',
  authLimiter,
  passwordResetValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { email } = req.body;

    const [users] = await executeQuery(`
      SELECT id, name, email FROM users WHERE email = ? AND status != 'deleted'
    `, [email]);

    // Always return success to prevent email enumeration
    if (users.length === 0) {
      return res.json({
        success: true,
        message: 'If an account with that email exists, a reset link has been sent.'
      });
    }

    const user = users[0];
    const resetToken = generateVerificationToken();
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store reset token
    await executeQuery(`
      UPDATE users 
      SET password_reset_token = ?, password_reset_expires = ?, updated_at = NOW()
      WHERE id = ?
    `, [resetToken, resetExpiry, user.id]);

    // Send reset email
    try {
      await notificationService.sendEmail({
        to: email,
        subject: 'Password Reset Request',
        html: notificationService.emailTemplates.passwordReset({
          name: user.name,
          token: resetToken
        }).html
      });
    } catch (error) {
      console.error('Failed to send password reset email:', error);
      // Don't throw error to prevent revealing email existence
    }

    res.json({
      success: true,
      message: 'If an account with that email exists, a reset link has been sent.'
    });
  })
);

/**
 * Reset Password
 * POST /api/auth/reset-password
 */
router.post('/reset-password',
  authLimiter,
  passwordResetConfirmValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { token, password } = req.body;

    const [users] = await executeQuery(`
      SELECT id, name, email, password_reset_token, password_reset_expires
      FROM users 
      WHERE password_reset_token = ? AND password_reset_expires > NOW()
    `, [token]);

    if (users.length === 0) {
      throw new ValidationError('Invalid or expired reset token');
    }

    const user = users[0];
    const hashedPassword = await hashPassword(password);

    // Update password and clear reset token
    await executeQuery(`
      UPDATE users 
      SET password = ?, password_reset_token = NULL, password_reset_expires = NULL,
          failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
      WHERE id = ?
    `, [hashedPassword, user.id]);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  })
);

// ================================================================
// ACCOUNT STATUS ROUTES
// ================================================================

/**
 * Get Current User Status
 * GET /api/auth/me
 */
router.get('/me',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const [users] = await executeQuery(`
      SELECT 
        id, name, email, phone, user_type, status, created_at,
        email_verified_at, phone_verified_at, last_login_at,
        license_number, agency_name, experience_years, commission_rate,
        specialization, agent_bio, preferred_agent_id
      FROM users 
      WHERE id = ?
    `, [userId]);

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];
    user.email_verified = !!user.email_verified_at;
    user.phone_verified = !!user.phone_verified_at;

    res.json({
      success: true,
      data: { user }
    });
  })
);

/**
 * Check Email Availability
 * POST /api/auth/check-email
 */
router.post('/check-email',
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
      throw new ValidationError('Email address required');
    }

    const [users] = await executeQuery(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    res.json({
      success: true,
      data: {
        available: users.length === 0,
        email
      }
    });
  })
);

// ================================================================
// EXPORT ROUTER
// ================================================================

module.exports = router;