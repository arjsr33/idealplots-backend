// ================================================================
// BACKEND/ROUTES/USERS.JS - USER PROFILE MANAGEMENT ROUTES
// FIXED: Now matches the actual database schema from paste.txt
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const { body, param, validationResult } = require('express-validator');

// Import middleware and services
const { 
  authenticateToken, 
  requireOwnershipOrAdmin,
  hashPassword,
  comparePassword
} = require('../middleware/auth');

const { 
  asyncHandler, 
  ValidationError, 
  NotFoundError,
  DuplicateError,
  AuthenticationError
} = require('../middleware/errorHandler');

const { executeQuery, executeTransaction, handleDatabaseError } = require('../database/connection');

const router = express.Router();

// ================================================================
// RATE LIMITING
// ================================================================

const profileUpdateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 profile updates per window
  message: {
    success: false,
    error: 'Too many profile update attempts, please try again later.'
  }
});

// ================================================================
// FILE UPLOAD CONFIGURATION
// ================================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, process.env.UPLOAD_PATH || './uploads/profiles/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = path.extname(file.originalname);
    cb(null, `profile-${req.user.id}-${uniqueSuffix}${extension}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new ValidationError('Only JPEG, PNG, and GIF images are allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.UPLOAD_MAX_SIZE) || 5 * 1024 * 1024, // 5MB
    files: 1
  }
});

// ================================================================
// VALIDATION RULES (FIXED TO MATCH ACTUAL SCHEMA)
// ================================================================

const profileUpdateValidation = [
  body('name')
    .optional()
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Name must be between 2-255 characters'),
  
  body('phone')
    .optional()
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage('Valid phone number required (E.164 format)'),
  
  body('gender')
    .optional()
    .isIn(['male', 'female', 'other'])
    .withMessage('Gender must be male, female, or other'),
  
  body('address')
    .optional()
    .isLength({ max: 1000 })
    .trim()
    .withMessage('Address must be under 1000 characters'),
  
  body('city')
    .optional()
    .isLength({ max: 100 })
    .trim()
    .withMessage('City must be under 100 characters'),
  
  body('state')
    .optional()
    .isLength({ max: 100 })
    .trim()
    .withMessage('State must be under 100 characters'),
  
  body('pincode')
    .optional()
    .isLength({ max: 10 })
    .trim()
    .withMessage('Pincode must be under 10 characters'),
  
  // User preference fields from schema
  body('is_buyer')
    .optional()
    .isBoolean()
    .withMessage('is_buyer must be boolean'),
  
  body('is_seller')
    .optional()
    .isBoolean()
    .withMessage('is_seller must be boolean'),
  
  body('preferred_property_types')
    .optional()
    .custom((value) => {
      const validTypes = ['villa', 'apartment', 'house', 'plot', 'commercial'];
      if (value && Array.isArray(value)) {
        return value.every(type => validTypes.includes(type));
      }
      return true;
    })
    .withMessage('Invalid property types'),
  
  body('budget_min')
    .optional()
    .isDecimal()
    .withMessage('Budget min must be a valid decimal'),
  
  body('budget_max')
    .optional()
    .isDecimal()
    .withMessage('Budget max must be a valid decimal'),
  
  body('preferred_cities')
    .optional()
    .custom((value) => {
      const validCities = [
        'Thiruvananthapuram', 'Kochi', 'Kozhikode', 'Thrissur', 'Kollam', 
        'Palakkad', 'Alappuzha', 'Kottayam', 'Kannur', 'Kasaragod', 
        'Malappuram', 'Pathanamthitta', 'Idukki', 'Wayanad'
      ];
      if (value && Array.isArray(value)) {
        return value.every(city => validCities.includes(city));
      }
      return true;
    })
    .withMessage('Invalid preferred cities'),
  
  body('preferred_bedrooms')
    .optional()
    .custom((value) => {
      const validBedrooms = ['1', '2', '3', '4', '5+'];
      if (value && Array.isArray(value)) {
        return value.every(bedroom => validBedrooms.includes(bedroom));