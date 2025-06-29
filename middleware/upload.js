// ================================================================
// BACKEND/MIDDLEWARE/UPLOAD.JS - FILE UPLOAD MIDDLEWARE
// Based on actual database schema: property_images + user profile_image
// Supports both development (local) and production (Hostinger) environments
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
  
  // Allowed file types
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
      base: '/home/u472925267/public_html/uploads', // Hostinger path
      properties: '/home/u472925267/public_html/uploads/properties',
      profiles: '/home/u472925267/public_html/uploads/profiles'
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
  }
};

// ================================================================
// UTILITY FUNCTIONS
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
 * Generate unique filename
 * @param {string} originalName - Original filename
 * @param {string} prefix - Filename prefix
 * @param {number} userId - User ID for security
 * @returns {string} Unique filename
 */
const generateUniqueFilename = (originalName, prefix, userId = null) => {
  const timestamp = Date.now();
  const randomString = crypto.randomBytes(8).toString('hex');
  const extension = path.extname(originalName).toLowerCase();
  const userPart = userId ? `-${userId}` : '';
  
  return `${prefix}${userPart}-${timestamp}-${randomString}${extension}`;
};

/**
 * Ensure directory exists
 * @param {string} dirPath - Directory path
 */
const ensureDirectoryExists = async (dirPath) => {
  try {
    await fs.access(dirPath);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.mkdir(dirPath, { recursive: true });
    } else {
      throw error;
    }
  }
};

/**
 * Process image with Sharp
 * @param {string} inputPath - Input file path
 * @param {string} outputPath - Output file path
 * @param {object} options - Processing options
 */
const processImage = async (inputPath, outputPath, options) => {
  try {
    await sharp(inputPath)
      .resize(options.width, options.height, {
        fit: 'cover',
        position: 'center'
      })
      .jpeg({ quality: options.quality })
      .toFile(outputPath);
  } catch (error) {
    console.error('Image processing error:', error);
    throw new FileUploadError('Failed to process image');
  }
};

/**
 * Delete file safely
 * @param {string} filePath - File path to delete
 */
const deleteFileSafe = async (filePath) => {
  try {
    await fs.unlink(filePath);
  } catch (error) {
    console.error('Error deleting file:', filePath, error.message);
  }
};

// ================================================================
// MULTER STORAGE CONFIGURATIONS
// ================================================================

/**
 * Storage configuration for property images
 */
const propertyImageStorage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      const uploadPaths = getUploadPaths();
      await ensureDirectoryExists(uploadPaths.properties);
      cb(null, uploadPaths.properties);
    } catch (error) {
      cb(new FileUploadError('Failed to create upload directory'), null);
    }
  },
  filename: (req, file, cb) => {
    try {
      const propertyId = req.params.propertyId || req.params.id;
      const filename = generateUniqueFilename(file.originalname, 'property', propertyId);
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
      await ensureDirectoryExists(uploadPaths.profiles);
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
      const filename = generateUniqueFilename(file.originalname, 'profile', userId);
      cb(null, filename);
    } catch (error) {
      cb(new FileUploadError('Failed to generate filename'), null);
    }
  }
});

// ================================================================
// FILE FILTERS
// ================================================================

/**
 * File filter for images
 * @param {object} req - Express request
 * @param {object} file - Multer file object
 * @param {function} cb - Callback function
 */
const imageFileFilter = (req, file, cb) => {
  if (UPLOAD_CONFIG.ALLOWED_TYPES.images.includes(file.mimetype)) {
    cb(null, true);
  } else {
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
// MIDDLEWARE FUNCTIONS
// ================================================================

/**
 * Handle property images upload
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Next middleware
 */
const handlePropertyImagesUpload = async (req, res, next) => {
  uploadPropertyImages(req, res, async (error) => {
    if (error) {
      if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
          return next(new FileUploadError('File size too large. Maximum size is 5MB per image.'));
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
          return next(new FileUploadError(`Too many files. Maximum is ${UPLOAD_CONFIG.MAX_FILES.property_images} images.`));
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
          return next(new FileUploadError('Unexpected field name. Use "images" field name.'));
        }
      }
      return next(error);
    }
    
    if (!req.files || req.files.length === 0) {
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
            
            await processImage(originalPath, processedPath, sizeConfig);
            
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
      next();
      
    } catch (error) {
      // Clean up uploaded files on error
      for (const file of req.files) {
        await deleteFileSafe(file.path);
      }
      next(new FileUploadError('Failed to process images'));
    }
  });
};

/**
 * Handle profile image upload
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Next middleware
 */
const handleProfileImageUpload = async (req, res, next) => {
  uploadProfileImage(req, res, async (error) => {
    if (error) {
      if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
          return next(new FileUploadError('File size too large. Maximum size is 2MB.'));
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
          return next(new FileUploadError('Unexpected field name. Use "profile_image" field name.'));
        }
      }
      return next(error);
    }
    
    if (!req.file) {
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
        
        await processImage(originalPath, processedPath, sizeConfig);
        
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
      
      next();
      
    } catch (error) {
      // Clean up uploaded file on error
      await deleteFileSafe(req.file.path);
      next(new FileUploadError('Failed to process profile image'));
    }
  });
};

// ================================================================
// DATABASE OPERATIONS
// ================================================================

/**
 * Save property images to database
 * @param {number} propertyId - Property ID
 * @param {array} processedImages - Processed images data
 * @param {object} options - Additional options
 * @returns {array} Saved image records
 */
const savePropertyImages = async (propertyId, processedImages, options = {}) => {
  const savedImages = [];
  
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
  
  return savedImages;
};

/**
 * Update user profile image in database
 * @param {number} userId - User ID
 * @param {object} processedImage - Processed image data
 * @returns {object} Update result
 */
const updateUserProfileImage = async (userId, processedImage) => {
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
  
  // Clean up old profile image
  if (oldImageUrl) {
    const uploadPaths = getUploadPaths();
    const oldImagePath = path.join(uploadPaths.profiles, path.basename(oldImageUrl));
    await deleteFileSafe(oldImagePath);
  }
  
  return {
    user_id: userId,
    profile_image: processedImage.variants.medium.url,
    variants: processedImage.variants
  };
};

/**
 * Delete property image
 * @param {number} imageId - Image ID
 * @param {number} propertyId - Property ID (for security)
 * @returns {boolean} Success status
 */
const deletePropertyImage = async (imageId, propertyId) => {
  // Get image details
  const [images] = await executeQuery(`
    SELECT image_path FROM property_images 
    WHERE id = ? AND property_id = ?
  `, [imageId, propertyId]);
  
  if (images.length === 0) {
    throw new ValidationError('Image not found');
  }
  
  const imagePath = images[0].image_path;
  
  // Delete from database
  await executeQuery(`
    DELETE FROM property_images 
    WHERE id = ? AND property_id = ?
  `, [imageId, propertyId]);
  
  // Delete file
  await deleteFileSafe(imagePath);
  
  return true;
};

// ================================================================
// CLEANUP FUNCTIONS
// ================================================================

/**
 * Clean up orphaned files (files not in database)
 * @param {string} uploadType - 'properties' or 'profiles'
 */
const cleanupOrphanedFiles = async (uploadType) => {
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
          await deleteFileSafe(path.join(uploadDir, file));
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
          await deleteFileSafe(path.join(uploadDir, file));
        }
      }
    }
    
    console.log(`Cleaned up orphaned ${uploadType} files`);
  } catch (error) {
    console.error(`Error cleaning up ${uploadType} files:`, error);
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
    etag: true
  }));
  
  // Serve profile images
  app.use(urlPrefixes.profiles, express.static(uploadPaths.profiles, {
    maxAge: '7d', // Cache for 7 days
    etag: true
  }));
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
  
  // Configuration
  getUploadPaths,
  getUrlPrefixes,
  UPLOAD_CONFIG,
  
  // Direct multer instances (for custom usage)
  uploadPropertyImages,
  uploadProfileImage
};

// ================================================================
// USAGE EXAMPLES
// ================================================================

/*
// In routes/properties.js - Upload property images
router.post('/:id/images', 
  authenticateToken,
  requireOwnershipOrAdmin,
  handlePropertyImagesUpload,
  async (req, res) => {
    try {
      const propertyId = req.params.id;
      const savedImages = await savePropertyImages(propertyId, req.processedImages);
      
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

// In routes/users.js - Upload profile image
router.post('/profile/image',
  authenticateToken,
  handleProfileImageUpload,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const result = await updateUserProfileImage(userId, req.processedProfileImage);
      
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

// In app.js - Setup static file serving
const upload = require('./middleware/upload');
upload.setupStaticFileServing(app);

// Cleanup job (run daily)
const cron = require('node-cron');
cron.schedule('0 2 * * *', async () => {
  await cleanupOrphanedFiles('properties');
  await cleanupOrphanedFiles('profiles');
});
*/