// ================================================================
// BACKEND/MIDDLEWARE/UPLOAD.JS - ENHANCED FILE UPLOAD MIDDLEWARE WITH AUDIT LOGGING
// Based on actual database schema: property_images + user profile_image
// Supports both development (local) and production (Hostinger) environments
// Includes comprehensive audit logging for security and compliance
// ================================================================

const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const sharp = require('sharp'); // For image processing and optimization

const { 
  ValidationError, 
  FileUploadError 
} = require('./errorHandler');

const { executeQuery } = require('../database/connection');

// ✅ IMPORT AUDIT SERVICE FOR COMPREHENSIVE LOGGING
const auditService = require('../services/auditService');

// ================================================================
// CONFIGURATION CONSTANTS
// ================================================================

const UPLOAD_CONFIG = {
  // File size limits (in bytes)
  MAX_FILE_SIZE: {
    property_image: parseInt(process.env.UPLOAD_MAX_PROPERTY_IMAGE_SIZE) || 5 * 1024 * 1024, // 5MB
    profile_image: parseInt(process.env.UPLOAD_MAX_PROFILE_IMAGE_SIZE) || 2 * 1024 * 1024 // 2MB
  },
  
  // Maximum number of files per upload
  MAX_FILES: {
    property_images: parseInt(process.env.UPLOAD_MAX_PROPERTY_IMAGES) || 10,
    profile_image: 1
  },
  
  // Allowed file types (IMAGES ONLY)
  ALLOWED_TYPES: {
    images: ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']
  },
  
  // Base upload paths - Environment-dependent
  PATHS: {
    development: {
      base: './uploads',
      properties: './uploads/properties',
      profiles: './uploads/profiles'
    },
    production: {
      base: '/home/username/public_html/uploads', // Update with actual Hostinger path
      properties: '/home/username/public_html/uploads/properties',
      profiles: '/home/username/public_html/uploads/profiles'
    }
  },
  
  // URL prefixes for serving files
  URL_PREFIXES: {
    development: {
      properties: '/uploads/properties',
      profiles: '/uploads/profiles'
    },
    production: {
      properties: '/uploads/properties',
      profiles: '/uploads/profiles'
    }
  },
  
  // Image processing settings
  IMAGE_PROCESSING: {
    // Property images
    property: {
      thumbnail: { width: 300, height: 200, quality: 80 },
      medium: { width: 600, height: 400, quality: 85 },
      large: { width: 1200, height: 800, quality: 90 }
    },
    // Profile images
    profile: {
      thumbnail: { width: 100, height: 100, quality: 80 },
      medium: { width: 300, height: 300, quality: 85 }
    }
  },
  
  // Security settings
  SECURITY: {
    // Scan for malicious file patterns
    FORBIDDEN_EXTENSIONS: ['.exe', '.bat', '.sh', '.php', '.asp', '.aspx', '.jsp'],
    FORBIDDEN_PATTERNS: ['<script', '<?php', '<%', 'javascript:', 'vbscript:'],
    MAX_FILENAME_LENGTH: 255
  }
};

// ================================================================
// UTILITY FUNCTIONS WITH AUDIT LOGGING
// ================================================================

/**
 * Get current environment
 * @returns {string} 'development' or 'production'
 */
const getEnvironment = () => {
  return process.env.NODE_ENV === 'production' ? 'production' : 'development';
};

/**
 * Get upload paths for current environment
 * @returns {object} Upload paths
 */
const getUploadPaths = () => {
  return UPLOAD_CONFIG.PATHS[getEnvironment()];
};

/**
 * Get URL prefixes for current environment
 * @returns {object} URL prefixes
 */
const getUrlPrefixes = () => {
  return UPLOAD_CONFIG.URL_PREFIXES[getEnvironment()];
};

/**
 * Generate unique filename with security checks and audit logging
 * @param {string} originalName - Original filename
 * @param {string} prefix - Filename prefix
 * @param {number} userId - User ID for security
 * @param {object} req - Express request for audit
 * @returns {string} Unique filename
 */
const generateUniqueFilename = (originalName, prefix, userId = null, req = null) => {
  // Security check: validate filename length
  if (originalName.length > UPLOAD_CONFIG.SECURITY.MAX_FILENAME_LENGTH) {
    throw new ValidationError('Filename too long');
  }
  
  // Security check: forbidden extensions
  const extension = path.extname(originalName).toLowerCase();
  if (UPLOAD_CONFIG.SECURITY.FORBIDDEN_EXTENSIONS.includes(extension)) {
    throw new ValidationError('File type not allowed for security reasons');
  }
  
  // Security check: scan for malicious patterns in filename
  const filename = originalName.toLowerCase();
  for (const pattern of UPLOAD_CONFIG.SECURITY.FORBIDDEN_PATTERNS) {
    if (filename.includes(pattern)) {
      // ✅ AUDIT MALICIOUS FILE ATTEMPT
      if (req && userId) {
        auditService.logSecurityEvent({
          eventType: 'malicious_file_upload_attempt',
          userId,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          severity: 'high',
          details: {
            originalFilename: originalName,
            detectedPattern: pattern,
            uploadType: prefix,
            attemptTime: new Date().toISOString()
          }
        }).catch(console.error);
      }
      throw new ValidationError('File contains potentially malicious content');
    }
  }
  
  const timestamp = Date.now();
  const randomString = crypto.randomBytes(8).toString('hex');
  const userPart = userId ? `-${userId}` : '';
  
  return `${prefix}${userPart}-${timestamp}-${randomString}${extension}`;
};

/**
 * Ensure directory exists with audit logging
 * @param {string} dirPath - Directory path
 * @param {object} req - Express request for audit
 */
const ensureDirectoryExists = async (dirPath, req = null) => {
  try {
    await fs.access(dirPath);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.mkdir(dirPath, { recursive: true });
      
      // ✅ AUDIT DIRECTORY CREATION
      if (req) {
        auditService.logSecurityEvent({
          eventType: 'upload_directory_created',
          userId: req.user?.id,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          severity: 'low',
          details: {
            directoryPath: dirPath,
            environment: getEnvironment(),
            createdAt: new Date().toISOString()
          }
        }).catch(console.error);
      }
    } else {
      throw error;
    }
  }
};

/**
 * Process image with Sharp and audit logging
 * @param {string} inputPath - Input file path
 * @param {string} outputPath - Output file path
 * @param {object} options - Processing options
 * @param {object} auditData - Audit data
 */
const processImage = async (inputPath, outputPath, options, auditData = {}) => {
  try {
    await sharp(inputPath)
      .resize(options.width, options.height, {
        fit: 'cover',
        position: 'center'
      })
      .jpeg({ quality: options.quality })
      .toFile(outputPath);
    
    // ✅ AUDIT IMAGE PROCESSING
    if (auditData.req && auditData.userId) {
      auditService.logUserAction({
        userId: auditData.userId,
        action: 'image_processed',
        targetTable: 'file_processing',
        changes: {
          inputPath: path.basename(inputPath),
          outputPath: path.basename(outputPath),
          processing: options,
          imageType: auditData.imageType
        },
        ipAddress: auditData.req.ip,
        userAgent: auditData.req.get('User-Agent')
      }).catch(console.error);
    }
  } catch (error) {
    console.error('Image processing error:', error);
    
    // ✅ AUDIT IMAGE PROCESSING FAILURE
    if (auditData.req && auditData.userId) {
      auditService.logSecurityEvent({
        eventType: 'image_processing_failed',
        userId: auditData.userId,
        ipAddress: auditData.req.ip,
        userAgent: auditData.req.get('User-Agent'),
        severity: 'medium',
        details: {
          inputPath: path.basename(inputPath),
          processing: options,
          error: error.message,
          imageType: auditData.imageType
        }
      }).catch(console.error);
    }
    
    throw new FileUploadError('Failed to process image');
  }
};

/**
 * Delete file safely with audit logging
 * @param {string} filePath - File path to delete
 * @param {object} auditData - Audit data
 */
const deleteFileSafe = async (filePath, auditData = {}) => {
  try {
    await fs.unlink(filePath);
    
    // ✅ AUDIT FILE DELETION
    if (auditData.req && auditData.userId) {
      auditService.logUserAction({
        userId: auditData.userId,
        action: 'file_deleted',
        targetTable: 'file_operations',
        changes: {
          filePath: path.basename(filePath),
          reason: auditData.reason || 'file_cleanup',
          deletedAt: new Date().toISOString()
        },
        ipAddress: auditData.req.ip,
        userAgent: auditData.req.get('User-Agent')
      }).catch(console.error);
    }
  } catch (error) {
    console.error('Error deleting file:', filePath, error.message);
  }
};

// ================================================================
// MULTER STORAGE CONFIGURATIONS WITH AUDIT
// ================================================================

/**
 * Storage configuration for property images
 */
const propertyImageStorage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      const uploadPaths = getUploadPaths();
      await ensureDirectoryExists(uploadPaths.properties, req);
      cb(null, uploadPaths.properties);
    } catch (error) {
      cb(new FileUploadError('Failed to create upload directory'), null);
    }
  },
  filename: (req, file, cb) => {
    try {
      const propertyId = req.params.propertyId || req.params.id;
      const userId = req.user?.id;
      const filename = generateUniqueFilename(file.originalname, 'property', propertyId, req);
      
      // ✅ AUDIT PROPERTY IMAGE UPLOAD START
      auditService.logUserAction({
        userId,
        action: 'property_image_upload_started',
        targetTable: 'property_images',
        targetRecordId: propertyId,
        changes: {
          originalFilename: file.originalname,
          generatedFilename: filename,
          fileSize: file.size,
          mimeType: file.mimetype
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
      
      cb(null, filename);
    } catch (error) {
      cb(new FileUploadError('Failed to generate filename'), null);
    }
  }
});

/**
 * Storage configuration for profile images
 */
const profileImageStorage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      const uploadPaths = getUploadPaths();
      await ensureDirectoryExists(uploadPaths.profiles, req);
      cb(null, uploadPaths.profiles);
    } catch (error) {
      cb(new FileUploadError('Failed to create upload directory'), null);
    }
  },
  filename: (req, file, cb) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return cb(new ValidationError('User authentication required'), null);
      }
      const filename = generateUniqueFilename(file.originalname, 'profile', userId, req);
      
      // ✅ AUDIT PROFILE IMAGE UPLOAD START
      auditService.logUserAction({
        userId,
        action: 'profile_image_upload_started',
        targetTable: 'users',
        targetRecordId: userId,
        changes: {
          originalFilename: file.originalname,
          generatedFilename: filename,
          fileSize: file.size,
          mimeType: file.mimetype
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
      
      cb(null, filename);
    } catch (error) {
      cb(new FileUploadError('Failed to generate filename'), null);
    }
  }
});

// ================================================================
// FILE FILTERS WITH AUDIT
// ================================================================

/**
 * File filter for images with security checks and audit logging
 * @param {object} req - Express request
 * @param {object} file - Multer file object
 * @param {function} cb - Callback function
 */
const imageFileFilter = (req, file, cb) => {
  const userId = req.user?.id;
  
  if (UPLOAD_CONFIG.ALLOWED_TYPES.images.includes(file.mimetype)) {
    cb(null, true);
  } else {
    // ✅ AUDIT REJECTED FILE TYPE
    auditService.logSecurityEvent({
      eventType: 'rejected_file_type',
      userId,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'low',
      details: {
        rejectedMimeType: file.mimetype,
        originalFilename: file.originalname,
        allowedTypes: UPLOAD_CONFIG.ALLOWED_TYPES.images,
        rejectionReason: 'invalid_mime_type'
      }
    }).catch(console.error);
    
    cb(new ValidationError('Only JPEG, PNG, GIF, and WebP images are allowed'), false);
  }
};

// ================================================================
// MULTER UPLOAD INSTANCES
// ================================================================

/**
 * Property images upload (multiple files)
 */
const uploadPropertyImages = multer({
  storage: propertyImageStorage,
  fileFilter: imageFileFilter,
  limits: {
    fileSize: UPLOAD_CONFIG.MAX_FILE_SIZE.property_image,
    files: UPLOAD_CONFIG.MAX_FILES.property_images
  }
}).array('images', UPLOAD_CONFIG.MAX_FILES.property_images);

/**
 * Profile image upload (single file)
 */
const uploadProfileImage = multer({
  storage: profileImageStorage,
  fileFilter: imageFileFilter,
  limits: {
    fileSize: UPLOAD_CONFIG.MAX_FILE_SIZE.profile_image,
    files: UPLOAD_CONFIG.MAX_FILES.profile_image
  }
}).single('profile_image');

// ================================================================
// ENHANCED MIDDLEWARE FUNCTIONS WITH COMPREHENSIVE AUDIT
// ================================================================

/**
 * Handle property images upload with comprehensive audit logging
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Next middleware
 */
const handlePropertyImagesUpload = async (req, res, next) => {
  const startTime = Date.now();
  const userId = req.user?.id;
  const propertyId = req.params.propertyId || req.params.id;
  
  uploadPropertyImages(req, res, async (error) => {
    if (error) {
      // ✅ AUDIT UPLOAD ERRORS
      let errorType = 'upload_error';
      let severity = 'medium';
      
      if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
          errorType = 'file_size_exceeded';
          severity = 'low';
          
          auditService.logSecurityEvent({
            eventType: errorType,
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            severity,
            details: {
              uploadType: 'property_images',
              propertyId,
              maxAllowedSize: UPLOAD_CONFIG.MAX_FILE_SIZE.property_image,
              error: error.message
            }
          }).catch(console.error);
          
          return next(new FileUploadError('File size too large. Maximum size is 5MB per image.'));
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
          errorType = 'file_count_exceeded';
          
          auditService.logSecurityEvent({
            eventType: errorType,
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            severity,
            details: {
              uploadType: 'property_images',
              propertyId,
              maxAllowedFiles: UPLOAD_CONFIG.MAX_FILES.property_images,
              error: error.message
            }
          }).catch(console.error);
          
          return next(new FileUploadError(`Too many files. Maximum is ${UPLOAD_CONFIG.MAX_FILES.property_images} images.`));
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
          errorType = 'unexpected_field_name';
          
          auditService.logSecurityEvent({
            eventType: errorType,
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            severity,
            details: {
              uploadType: 'property_images',
              propertyId,
              expectedFieldName: 'images',
              error: error.message
            }
          }).catch(console.error);
          
          return next(new FileUploadError('Unexpected field name. Use "images" field name.'));
        }
      }
      
      // ✅ AUDIT GENERAL UPLOAD ERROR
      auditService.logSecurityEvent({
        eventType: 'property_upload_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'medium',
        details: {
          uploadType: 'property_images',
          propertyId,
          error: error.message,
          errorType: error.constructor.name
        }
      }).catch(console.error);
      
      return next(error);
    }
    
    if (!req.files || req.files.length === 0) {
      // ✅ AUDIT NO FILES PROVIDED
      auditService.logUserAction({
        userId,
        action: 'property_upload_no_files',
        targetTable: 'property_images',
        targetRecordId: propertyId,
        changes: {
          uploadAttempt: true,
          filesProvided: 0,
          reason: 'no_files_in_request'
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
      
      return next(new ValidationError('At least one image file is required'));
    }
    
    try {
      // Process uploaded images
      const uploadPaths = getUploadPaths();
      const urlPrefixes = getUrlPrefixes();
      const processedImages = [];
      
      for (const file of req.files) {
        const baseName = path.parse(file.filename).name;
        const originalPath = file.path;
        
        // Generate different sizes
        const sizes = UPLOAD_CONFIG.IMAGE_PROCESSING.property;
        const imageVariants = {
          original: {
            path: originalPath,
            url: `${urlPrefixes.properties}/${file.filename}`,
            size: file.size
          }
        };
        
        // Process thumbnail and medium sizes
        for (const [sizeName, sizeConfig] of Object.entries(sizes)) {
          if (sizeName !== 'large') { // Skip large for now to save space
            const processedFilename = `${baseName}-${sizeName}.jpg`;
            const processedPath = path.join(uploadPaths.properties, processedFilename);
            
            await processImage(originalPath, processedPath, sizeConfig, {
              req,
              userId,
              imageType: 'property_image'
            });
            
            imageVariants[sizeName] = {
              path: processedPath,
              url: `${urlPrefixes.properties}/${processedFilename}`,
              size: (await fs.stat(processedPath)).size
            };
          }
        }
        
        processedImages.push({
          original_filename: file.originalname,
          filename: file.filename,
          variants: imageVariants,
          file_size: file.size,
          mimetype: file.mimetype
        });
      }
      
      req.processedImages = processedImages;
      
      // ✅ AUDIT SUCCESSFUL PROPERTY IMAGES UPLOAD
      const processingTime = Date.now() - startTime;
      auditService.logUserAction({
        userId,
        action: 'property_images_uploaded',
        targetTable: 'property_images',
        targetRecordId: propertyId,
        changes: {
          filesUploaded: processedImages.length,
          totalFileSize: processedImages.reduce((sum, img) => sum + img.file_size, 0),
          processingTimeMs: processingTime,
          imageVariants: Object.keys(processedImages[0]?.variants || {}),
          environment: getEnvironment()
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
      
      next();
      
    } catch (error) {
      // Clean up uploaded files on error
      for (const file of req.files) {
        await deleteFileSafe(file.path, {
          req,
          userId,
          reason: 'processing_error_cleanup'
        });
      }
      
      // ✅ AUDIT PROCESSING ERROR
      auditService.logSecurityEvent({
        eventType: 'property_image_processing_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'medium',
        details: {
          propertyId,
          filesAttempted: req.files.length,
          error: error.message,
          processingStage: 'image_processing'
        }
      }).catch(console.error);
      
      next(new FileUploadError('Failed to process images'));
    }
  });
};

/**
 * Handle profile image upload with comprehensive audit logging
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Next middleware
 */
const handleProfileImageUpload = async (req, res, next) => {
  const startTime = Date.now();
  const userId = req.user?.id;
  
  uploadProfileImage(req, res, async (error) => {
    if (error) {
      // ✅ AUDIT PROFILE UPLOAD ERRORS
      let errorType = 'profile_upload_error';
      let severity = 'medium';
      
      if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
          errorType = 'profile_file_size_exceeded';
          severity = 'low';
          
          auditService.logSecurityEvent({
            eventType: errorType,
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            severity,
            details: {
              uploadType: 'profile_image',
              maxAllowedSize: UPLOAD_CONFIG.MAX_FILE_SIZE.profile_image,
              error: error.message
            }
          }).catch(console.error);
          
          return next(new FileUploadError('File size too large. Maximum size is 2MB.'));
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
          errorType = 'profile_unexpected_field';
          
          auditService.logSecurityEvent({
            eventType: errorType,
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            severity,
            details: {
              uploadType: 'profile_image',
              expectedFieldName: 'profile_image',
              error: error.message
            }
          }).catch(console.error);
          
          return next(new FileUploadError('Unexpected field name. Use "profile_image" field name.'));
        }
      }
      
      // ✅ AUDIT GENERAL PROFILE UPLOAD ERROR
      auditService.logSecurityEvent({
        eventType: 'profile_upload_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'medium',
        details: {
          uploadType: 'profile_image',
          error: error.message,
          errorType: error.constructor.name
        }
      }).catch(console.error);
      
      return next(error);
    }
    
    if (!req.file) {
      // ✅ AUDIT NO PROFILE FILE PROVIDED
      auditService.logUserAction({
        userId,
        action: 'profile_upload_no_file',
        targetTable: 'users',
        targetRecordId: userId,
        changes: {
          uploadAttempt: true,
          fileProvided: false,
          reason: 'no_file_in_request'
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
      
      return next(new ValidationError('Profile image file is required'));
    }
    
    try {
      // Process profile image
      const uploadPaths = getUploadPaths();
      const urlPrefixes = getUrlPrefixes();
      const baseName = path.parse(req.file.filename).name;
      const originalPath = req.file.path;
      
      // Generate different sizes for profile image
      const sizes = UPLOAD_CONFIG.IMAGE_PROCESSING.profile;
      const imageVariants = {
        original: {
          path: originalPath,
          url: `${urlPrefixes.profiles}/${req.file.filename}`,
          size: req.file.size
        }
      };
      
      // Process thumbnail and medium sizes
      for (const [sizeName, sizeConfig] of Object.entries(sizes)) {
        const processedFilename = `${baseName}-${sizeName}.jpg`;
        const processedPath = path.join(uploadPaths.profiles, processedFilename);
        
        await processImage(originalPath, processedPath, sizeConfig, {
          req,
          userId,
          imageType: 'profile_image'
        });
        
        imageVariants[sizeName] = {
          path: processedPath,
          url: `${urlPrefixes.profiles}/${processedFilename}`,
          size: (await fs.stat(processedPath)).size
        };
      }
      
      req.processedProfileImage = {
        original_filename: req.file.originalname,
        filename: req.file.filename,
        variants: imageVariants,
        file_size: req.file.size,
        mimetype: req.file.mimetype
      };
      
      // ✅ AUDIT SUCCESSFUL PROFILE IMAGE UPLOAD
      const processingTime = Date.now() - startTime;
      auditService.logUserAction({
        userId,
        action: 'profile_image_uploaded',
        targetTable: 'users',
        targetRecordId: userId,
        changes: {
          originalFilename: req.file.originalname,
          fileSize: req.file.size,
          processingTimeMs: processingTime,
          imageVariants: Object.keys(imageVariants),
          environment: getEnvironment()
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
      
      next();
      
    } catch (error) {
      // Clean up uploaded file on error
      await deleteFileSafe(req.file.path, {
        req,
        userId,
        reason: 'processing_error_cleanup'
      });
      
      // ✅ AUDIT PROFILE PROCESSING ERROR
      auditService.logSecurityEvent({
        eventType: 'profile_image_processing_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'medium',
        details: {
          originalFilename: req.file.originalname,
          fileSize: req.file.size,
          error: error.message,
          processingStage: 'image_processing'
        }
      }).catch(console.error);
      
      next(new FileUploadError('Failed to process profile image'));
    }
  });
};

// ================================================================
// DATABASE OPERATIONS WITH AUDIT LOGGING
// ================================================================

/**
 * Save property images to database with audit logging
 * @param {number} propertyId - Property ID
 * @param {array} processedImages - Processed images data
 * @param {object} options - Additional options
 * @param {object} req - Express request for audit
 * @returns {array} Saved image records
 */
const savePropertyImages = async (propertyId, processedImages, options = {}, req = null) => {
  const savedImages = [];
  const userId = req?.user?.id;
  
  try {
    for (let i = 0; i < processedImages.length; i++) {
      const image = processedImages[i];
      const displayOrder = options.startOrder ? options.startOrder + i : i;
      
      const [result] = await executeQuery(`
        INSERT INTO property_images (
          property_id, image_url, image_path, original_filename, 
          file_size, display_order, image_type, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `, [
        propertyId,
        image.variants.original.url,
        image.variants.original.path,
        image.original_filename,
        image.file_size,
        displayOrder,
        options.imageType || 'gallery'
      ]);
      
      savedImages.push({
        id: result.insertId,
        property_id: propertyId,
        image_url: image.variants.original.url,
        image_path: image.variants.original.path,
        original_filename: image.original_filename,
        file_size: image.file_size,
        display_order: displayOrder,
        image_type: options.imageType || 'gallery',
        variants: image.variants
      });
    }
    
    // ✅ AUDIT PROPERTY IMAGES SAVED TO DATABASE
    if (req && userId) {
      auditService.logUserAction({
        userId,
        action: 'property_images_saved_to_db',
        targetTable: 'property_images',
        targetRecordId: propertyId,
        changes: {
          imagesSaved: savedImages.length,
          totalFileSize: savedImages.reduce((sum, img) => sum + img.file_size, 0),
          imageIds: savedImages.map(img => img.id),
          imageType: options.imageType || 'gallery'
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
    }
    
    return savedImages;
    
  } catch (error) {
    // ✅ AUDIT DATABASE SAVE ERROR
    if (req && userId) {
      auditService.logSecurityEvent({
        eventType: 'property_images_db_save_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'high',
        details: {
          propertyId,
          imagesAttempted: processedImages.length,
          error: error.message,
          dbError: true
        }
      }).catch(console.error);
    }
    throw error;
  }
};

/**
 * Update user profile image in database with audit logging
 * @param {number} userId - User ID
 * @param {object} processedImage - Processed image data
 * @param {object} req - Express request for audit
 * @returns {object} Update result
 */
const updateUserProfileImage = async (userId, processedImage, req = null) => {
  try {
    // Get old profile image to delete
    const [oldImages] = await executeQuery(`
      SELECT profile_image FROM users WHERE id = ?
    `, [userId]);
    
    const oldImageUrl = oldImages[0]?.profile_image;
    
    // Update user profile image
    await executeQuery(`
      UPDATE users 
      SET profile_image = ?, updated_at = NOW() 
      WHERE id = ?
    `, [processedImage.variants.medium.url, userId]);
    
    // ✅ AUDIT PROFILE IMAGE UPDATE
    if (req) {
      auditService.logUserAction({
        userId,
        action: 'profile_image_updated',
        targetTable: 'users',
        targetRecordId: userId,
        changes: {
          newProfileImage: processedImage.variants.medium.url,
          originalFilename: processedImage.original_filename,
          fileSize: processedImage.file_size
        },
        previousData: {
          oldProfileImage: oldImageUrl
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
    }
    
    // Clean up old profile image
    if (oldImageUrl) {
      const uploadPaths = getUploadPaths();
      const oldImagePath = path.join(uploadPaths.profiles, path.basename(oldImageUrl));
      await deleteFileSafe(oldImagePath, {
        req,
        userId,
        reason: 'old_profile_image_cleanup'
      });
    }
    
    return {
      user_id: userId,
      profile_image: processedImage.variants.medium.url,
      variants: processedImage.variants
    };
    
  } catch (error) {
    // ✅ AUDIT PROFILE UPDATE ERROR
    if (req) {
      auditService.logSecurityEvent({
        eventType: 'profile_image_db_update_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'high',
        details: {
          originalFilename: processedImage.original_filename,
          fileSize: processedImage.file_size,
          error: error.message,
          dbError: true
        }
      }).catch(console.error);
    }
    throw error;
  }
};

/**
 * Delete property image with comprehensive audit logging
 * @param {number} imageId - Image ID
 * @param {number} propertyId - Property ID (for security)
 * @param {object} req - Express request for audit
 * @returns {boolean} Success status
 */
const deletePropertyImage = async (imageId, propertyId, req = null) => {
  const userId = req?.user?.id;
  
  try {
    // Get image details
    const [images] = await executeQuery(`
      SELECT image_path, original_filename, file_size FROM property_images 
      WHERE id = ? AND property_id = ?
    `, [imageId, propertyId]);
    
    if (images.length === 0) {
      // ✅ AUDIT IMAGE NOT FOUND
      if (req && userId) {
        auditService.logSecurityEvent({
          eventType: 'property_image_delete_not_found',
          userId,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          severity: 'medium',
          details: {
            imageId,
            propertyId,
            reason: 'image_not_found_or_unauthorized'
          }
        }).catch(console.error);
      }
      throw new ValidationError('Image not found');
    }
    
    const imageData = images[0];
    const imagePath = imageData.image_path;
    
    // Delete from database
    await executeQuery(`
      DELETE FROM property_images 
      WHERE id = ? AND property_id = ?
    `, [imageId, propertyId]);
    
    // ✅ AUDIT PROPERTY IMAGE DELETION
    if (req && userId) {
      auditService.logUserAction({
        userId,
        action: 'property_image_deleted',
        targetTable: 'property_images',
        targetRecordId: propertyId,
        changes: {
          deletedImageId: imageId,
          originalFilename: imageData.original_filename,
          fileSize: imageData.file_size,
          imagePath: path.basename(imagePath)
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
    }
    
    // Delete file
    await deleteFileSafe(imagePath, {
      req,
      userId,
      reason: 'property_image_deletion'
    });
    
    return true;
    
  } catch (error) {
    // ✅ AUDIT DELETION ERROR
    if (req && userId) {
      auditService.logSecurityEvent({
        eventType: 'property_image_delete_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'high',
        details: {
          imageId,
          propertyId,
          error: error.message,
          deletionStage: 'database_or_file_deletion'
        }
      }).catch(console.error);
    }
    throw error;
  }
};

// ================================================================
// CLEANUP FUNCTIONS WITH AUDIT LOGGING
// ================================================================

/**
 * Clean up orphaned files (files not in database) with audit logging
 * @param {string} uploadType - 'properties' or 'profiles'
 * @param {object} req - Express request for audit (optional)
 */
const cleanupOrphanedFiles = async (uploadType, req = null) => {
  const userId = req?.user?.id;
  let deletedCount = 0;
  let errorCount = 0;
  
  try {
    const uploadPaths = getUploadPaths();
    const uploadDir = uploadPaths[uploadType];
    
    // Get all files in directory
    const files = await fs.readdir(uploadDir);
    
    if (uploadType === 'properties') {
      // Get all property image paths from database
      const [dbImages] = await executeQuery(`
        SELECT image_path FROM property_images
      `);
      
      const dbPaths = dbImages.map(img => path.basename(img.image_path));
      
      // Delete files not in database
      for (const file of files) {
        if (!dbPaths.includes(file)) {
          try {
            await deleteFileSafe(path.join(uploadDir, file), {
              req,
              userId,
              reason: 'orphaned_file_cleanup'
            });
            deletedCount++;
          } catch (error) {
            errorCount++;
          }
        }
      }
    } else if (uploadType === 'profiles') {
      // Get all profile image URLs from database
      const [dbUsers] = await executeQuery(`
        SELECT profile_image FROM users WHERE profile_image IS NOT NULL
      `);
      
      const dbPaths = dbUsers.map(user => path.basename(user.profile_image));
      
      // Delete files not in database
      for (const file of files) {
        if (!dbPaths.includes(file)) {
          try {
            await deleteFileSafe(path.join(uploadDir, file), {
              req,
              userId,
              reason: 'orphaned_file_cleanup'
            });
            deletedCount++;
          } catch (error) {
            errorCount++;
          }
        }
      }
    }
    
    // ✅ AUDIT CLEANUP OPERATION
    if (req && userId) {
      auditService.logAdminAction({
        adminId: userId,
        action: 'file_cleanup_completed',
        targetTable: 'file_cleanup',
        changes: {
          uploadType,
          totalFilesScanned: files.length,
          orphanedFilesDeleted: deletedCount,
          deletionErrors: errorCount,
          environment: getEnvironment()
        },
        reason: 'Scheduled orphaned file cleanup',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'low'
      }).catch(console.error);
    }
    
    console.log(`Cleaned up orphaned ${uploadType} files: ${deletedCount} deleted, ${errorCount} errors`);
    
    return { deletedCount, errorCount };
    
  } catch (error) {
    // ✅ AUDIT CLEANUP ERROR
    if (req && userId) {
      auditService.logSecurityEvent({
        eventType: 'file_cleanup_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'medium',
        details: {
          uploadType,
          error: error.message,
          cleanupStage: 'directory_scan_or_comparison'
        }
      }).catch(console.error);
    }
    
    console.error(`Error cleaning up ${uploadType} files:`, error);
    throw error;
  }
};

/**
 * Get upload statistics with audit logging
 * @param {object} req - Express request for audit
 * @returns {object} Upload statistics
 */
const getUploadStatistics = async (req = null) => {
  const userId = req?.user?.id;
  
  try {
    // Get property images statistics
    const [propertyStats] = await executeQuery(`
      SELECT 
        COUNT(*) as total_images,
        SUM(file_size) as total_size,
        AVG(file_size) as avg_size,
        MIN(created_at) as oldest_image,
        MAX(created_at) as newest_image
      FROM property_images
    `);
    
    // Get profile images statistics
    const [profileStats] = await executeQuery(`
      SELECT 
        COUNT(*) as total_profiles_with_images,
        profile_image
      FROM users 
      WHERE profile_image IS NOT NULL
    `);
    
    // Get storage usage
    const uploadPaths = getUploadPaths();
    const propertyFiles = await fs.readdir(uploadPaths.properties);
    const profileFiles = await fs.readdir(uploadPaths.profiles);
    
    const stats = {
      property_images: {
        total_images: propertyStats[0].total_images,
        total_size_bytes: propertyStats[0].total_size || 0,
        average_size_bytes: propertyStats[0].avg_size || 0,
        oldest_image: propertyStats[0].oldest_image,
        newest_image: propertyStats[0].newest_image,
        files_on_disk: propertyFiles.length
      },
      profile_images: {
        total_profiles: profileStats[0].total_profiles_with_images,
        files_on_disk: profileFiles.length
      },
      storage: {
        environment: getEnvironment(),
        upload_paths: uploadPaths
      },
      generated_at: new Date().toISOString()
    };
    
    // ✅ AUDIT STATISTICS ACCESS
    if (req && userId) {
      auditService.logUserAction({
        userId,
        action: 'upload_statistics_accessed',
        targetTable: 'upload_statistics',
        changes: {
          statsGenerated: true,
          propertyImagesCount: stats.property_images.total_images,
          profileImagesCount: stats.profile_images.total_profiles,
          environment: getEnvironment()
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }).catch(console.error);
    }
    
    return stats;
    
  } catch (error) {
    // ✅ AUDIT STATISTICS ERROR
    if (req && userId) {
      auditService.logSecurityEvent({
        eventType: 'upload_statistics_failed',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'low',
        details: {
          error: error.message,
          statsStage: 'database_query_or_file_scan'
        }
      }).catch(console.error);
    }
    
    throw error;
  }
};

// ================================================================
// EXPRESS STATIC MIDDLEWARE SETUP
// ================================================================

/**
 * Setup static file serving for uploads
 * @param {object} app - Express app instance
 */
const setupStaticFileServing = (app) => {
  const uploadPaths = getUploadPaths();
  const urlPrefixes = getUrlPrefixes();
  
  // Serve property images
  app.use(urlPrefixes.properties, express.static(uploadPaths.properties, {
    maxAge: '30d', // Cache for 30 days
    etag: true,
    lastModified: true,
    setHeaders: (res, filePath) => {
      // Security headers for file serving
      res.set('X-Content-Type-Options', 'nosniff');
      res.set('X-Frame-Options', 'DENY');
      
      // Only allow image files
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
      const ext = path.extname(filePath).toLowerCase();
      
      if (!allowedExtensions.includes(ext)) {
        res.status(403).end();
        return;
      }
    }
  }));
  
  // Serve profile images
  app.use(urlPrefixes.profiles, express.static(uploadPaths.profiles, {
    maxAge: '7d', // Cache for 7 days
    etag: true,
    lastModified: true,
    setHeaders: (res, filePath) => {
      // Security headers for file serving
      res.set('X-Content-Type-Options', 'nosniff');
      res.set('X-Frame-Options', 'DENY');
      
      // Only allow image files
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
      const ext = path.extname(filePath).toLowerCase();
      
      if (!allowedExtensions.includes(ext)) {
        res.status(403).end();
        return;
      }
    }
  }));
};

// ================================================================
// SECURITY MONITORING FUNCTIONS
// ================================================================

/**
 * Monitor for suspicious upload patterns
 * @param {number} userId - User ID
 * @param {object} req - Express request
 */
const monitorSuspiciousUploads = async (userId, req) => {
  try {
    // Check for rapid multiple uploads
    const [recentUploads] = await executeQuery(`
      SELECT COUNT(*) as upload_count
      FROM audit_logs
      WHERE user_id = ?
        AND action LIKE '%_upload%'
        AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    `, [userId]);
    
    if (recentUploads[0].upload_count > 20) {
      auditService.logSecurityEvent({
        eventType: 'suspicious_upload_pattern',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'high',
        details: {
          pattern: 'rapid_multiple_uploads',
          uploadCount: recentUploads[0].upload_count,
          timeWindow: '5_minutes',
          threshold: 20
        }
      }).catch(console.error);
    }
    
    // Check for large file uploads
    // This would be implemented based on specific business rules
    
  } catch (error) {
    console.error('Error monitoring suspicious uploads:', error);
  }
};

// ================================================================
// EXPORT MODULE
// ================================================================

module.exports = {
  // Middleware functions
  handlePropertyImagesUpload,
  handleProfileImageUpload,
  
  // Database operations
  savePropertyImages,
  updateUserProfileImage,
  deletePropertyImage,
  
  // Utility functions
  generateUniqueFilename,
  ensureDirectoryExists,
  processImage,
  deleteFileSafe,
  cleanupOrphanedFiles,
  setupStaticFileServing,
  
  // Statistics and monitoring
  getUploadStatistics,
  monitorSuspiciousUploads,
  
  // Configuration
  getUploadPaths,
  getUrlPrefixes,
  UPLOAD_CONFIG,
  
  // Direct multer instances (for custom usage)
  uploadPropertyImages,
  uploadProfileImage
};

// ================================================================
// USAGE EXAMPLES WITH AUDIT LOGGING
// ================================================================

/*
// In routes/properties.js - Upload property images with audit
router.post('/:id/images', 
  authenticateToken,
  requireOwnershipOrAdmin,
  handlePropertyImagesUpload,
  async (req, res, next) => {
    try {
      const propertyId = req.params.id;
      const savedImages = await savePropertyImages(
        propertyId, 
        req.processedImages, 
        { imageType: 'gallery' },
        req // Pass req for audit logging
      );
      
      // Monitor for suspicious patterns
      await monitorSuspiciousUploads(req.user.id, req);
      
      res.json({
        success: true,
        message: `${savedImages.length} images uploaded successfully`,
        data: { images: savedImages }
      });
    } catch (error) {
      next(error);
    }
  }
);

// In routes/users.js - Upload profile image with audit
router.post('/profile/image',
  authenticateToken,
  handleProfileImageUpload,
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      const result = await updateUserProfileImage(
        userId, 
        req.processedProfileImage,
        req // Pass req for audit logging
      );
      
      res.json({
        success: true,
        message: 'Profile image updated successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }
);

// In routes/admin.js - Get upload statistics
router.get('/upload-stats',
  authenticateToken,
  requireAdmin,
  async (req, res, next) => {
    try {
      const stats = await getUploadStatistics(req);
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }
);

// In app.js - Setup static file serving
const upload = require('./middleware/upload');
upload.setupStaticFileServing(app);

// Cleanup job (run daily) with audit logging
const cron = require('node-cron');
cron.schedule('0 2 * * *', async () => {
  try {
    await cleanupOrphanedFiles('properties');
    await cleanupOrphanedFiles('profiles');
  } catch (error) {
    console.error('Scheduled cleanup failed:', error);
  }
});
*/