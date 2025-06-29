// ================================================================
// BACKEND/ROUTES/PROPERTIES.JS - PROPERTY MANAGEMENT ROUTES
// Handles property CRUD, search, images, and favorites
// ================================================================

const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// Import middleware and services
const { 
  authenticateToken, 
  optionalAuth,
  requireAdmin,
  requireAgent,
  requireAgentOrAdmin,
  requirePropertyOwnership,
  requireActiveAccount
} = require('../middleware/auth');

const {
  handlePropertyImagesUpload,
  handleProfileImageUpload
} = require('../middleware/upload');

const { 
  asyncHandler, 
  ValidationError, 
  NotFoundError,
  AuthorizationError 
} = require('../middleware/errorHandler');

const propertyService = require('../services/propertyService');

const router = express.Router();

// ================================================================
// RATE LIMITING
// ================================================================

const createPropertyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 property creations per hour
  message: {
    success: false,
    error: 'Too many property submissions. Please try again later.',
    retryAfter: '1 hour'
  }
});

const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 searches per minute
  message: {
    success: false,
    error: 'Too many search requests. Please slow down.'
  }
});

const updateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // 50 updates per window
  message: {
    success: false,
    error: 'Too many update requests. Please try again later.'
  }
});

// ================================================================
// VALIDATION RULES
// ================================================================

const createPropertyValidation = [
  body('title')
    .isLength({ min: 5, max: 255 })
    .trim()
    .withMessage('Title must be between 5-255 characters'),
  
  body('description')
    .isLength({ min: 20, max: 5000 })
    .trim()
    .withMessage('Description must be between 20-5000 characters'),
  
  body('property_type')
    .isIn([
      'residential_plot', 'commercial_plot', 'agricultural_land',
      'villa', 'apartment', 'house', 'commercial_building',
      'warehouse', 'shop', 'office_space'
    ])
    .withMessage('Invalid property type'),
  
  body('price')
    .isFloat({ min: 1 })
    .withMessage('Price must be a positive number'),
  
  body('area')
    .isFloat({ min: 1 })
    .withMessage('Area must be a positive number'),
  
  body('city')
    .isIn([
      'Thiruvananthapuram', 'Kochi', 'Kozhikode', 'Thrissur', 'Kollam',
      'Palakkad', 'Alappuzha', 'Kottayam', 'Kannur', 'Kasaragod',
      'Malappuram', 'Pathanamthitta', 'Idukki', 'Wayanad'
    ])
    .withMessage('Invalid city'),
  
  body('location')
    .isLength({ min: 2, max: 255 })
    .trim()
    .withMessage('Location must be between 2-255 characters'),
  
  body('address')
    .optional()
    .isLength({ max: 1000 })
    .trim()
    .withMessage('Address must be under 1000 characters'),
  
  body('latitude')
    .optional()
    .isFloat({ min: -90, max: 90 })
    .withMessage('Invalid latitude'),
  
  body('longitude')
    .optional()
    .isFloat({ min: -180, max: 180 })
    .withMessage('Invalid longitude'),
  
  body('bedrooms')
    .optional()
    .isInt({ min: 0, max: 20 })
    .withMessage('Bedrooms must be between 0-20'),
  
  body('bathrooms')
    .optional()
    .isInt({ min: 0, max: 20 })
    .withMessage('Bathrooms must be between 0-20'),
  
  body('parking')
    .optional()
    .isBoolean()
    .withMessage('Parking must be boolean'),
  
  body('furnished')
    .optional()
    .isBoolean()
    .withMessage('Furnished must be boolean'),
  
  body('features')
    .optional()
    .isArray()
    .withMessage('Features must be an array'),
  
  body('meta_title')
    .optional()
    .isLength({ max: 255 })
    .trim()
    .withMessage('Meta title must be under 255 characters'),
  
  body('meta_description')
    .optional()
    .isLength({ max: 500 })
    .trim()
    .withMessage('Meta description must be under 500 characters')
];

const updatePropertyValidation = createPropertyValidation.map(rule => {
  // Make all fields optional for updates
  return rule.optional();
});

const searchValidation = [
  query('search').optional().isLength({ max: 100 }).trim(),
  query('property_type').optional().isArray(),
  query('city').optional().isArray(),
  query('location').optional().isLength({ max: 100 }).trim(),
  query('price_min').optional().isFloat({ min: 0 }),
  query('price_max').optional().isFloat({ min: 0 }),
  query('area_min').optional().isFloat({ min: 0 }),
  query('area_max').optional().isFloat({ min: 0 }),
  query('bedrooms').optional().isArray(),
  query('bathrooms').optional().isInt({ min: 0 }),
  query('parking').optional().isBoolean(),
  query('furnished').optional().isBoolean(),
  query('sort_by').optional().isIn(['created_at', 'price', 'area', 'price_per_sqft', 'views_count', 'favorites_count']),
  query('sort_order').optional().isIn(['ASC', 'DESC']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('latitude').optional().isFloat({ min: -90, max: 90 }),
  query('longitude').optional().isFloat({ min: -180, max: 180 }),
  query('radius_km').optional().isFloat({ min: 0.1, max: 100 })
];

// ================================================================
// PUBLIC PROPERTY ROUTES
// ================================================================

/**
 * Get properties with search and filters (public)
 * GET /api/properties
 */
router.get('/',
  searchLimiter,
  optionalAuth,
  searchValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      search,
      property_type,
      city,
      location,
      price_min,
      price_max,
      area_min,
      area_max,
      bedrooms,
      bathrooms,
      parking,
      furnished,
      sort_by,
      sort_order,
      page = 1,
      limit = 12,
      latitude,
      longitude,
      radius_km
    } = req.query;

    const filters = {
      status: 'active' // Only show active properties publicly
    };

    // Apply search filters
    if (search) filters.search = search;
    if (property_type) filters.property_type = Array.isArray(property_type) ? property_type : [property_type];
    if (city) filters.city = Array.isArray(city) ? city : [city];
    if (location) filters.location = location;
    if (price_min) filters.price_min = parseFloat(price_min);
    if (price_max) filters.price_max = parseFloat(price_max);
    if (area_min) filters.area_min = parseFloat(area_min);
    if (area_max) filters.area_max = parseFloat(area_max);
    if (bedrooms) filters.bedrooms = Array.isArray(bedrooms) ? bedrooms.map(b => parseInt(b)) : [parseInt(bedrooms)];
    if (bathrooms) filters.bathrooms = parseInt(bathrooms);
    if (parking !== undefined) filters.parking = parking === 'true';
    if (furnished !== undefined) filters.furnished = furnished === 'true';
    if (latitude && longitude) {
      filters.latitude = parseFloat(latitude);
      filters.longitude = parseFloat(longitude);
      if (radius_km) filters.radius_km = parseFloat(radius_km);
    }

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit)
    };

    const sorting = {};
    if (sort_by) sorting.sort_by = sort_by;
    if (sort_order) sorting.sort_order = sort_order;

    const result = await propertyService.getProperties(filters, pagination, sorting);

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Get single property details (public)
 * GET /api/properties/:identifier
 */
router.get('/:identifier',
  optionalAuth,
  [param('identifier').notEmpty().withMessage('Property ID or slug required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { identifier } = req.params;
    const userId = req.user?.id;

    // Get property details
    const property = await propertyService.getPropertyDetails(identifier, true, userId);

    // Only show active properties to public
    if (property.status !== 'active' && (!req.user || req.user.user_type === 'user')) {
      throw new NotFoundError('Property not found');
    }

    // Record property view
    if (req.ip) {
      await propertyService.recordPropertyView(property.id, {
        user_id: userId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        session_id: req.sessionID,
        referrer_url: req.get('Referer')
      });
    }

    // Get similar properties
    const similarProperties = await propertyService.getSimilarProperties(property.id, 6);

    res.json({
      success: true,
      data: {
        property,
        similar_properties: similarProperties
      }
    });
  })
);

/**
 * Get property recommendations for user
 * GET /api/properties/user/recommendations
 */
router.get('/user/recommendations',
  authenticateToken,
  [
    query('limit').optional().isInt({ min: 1, max: 20 }),
    query('exclude').optional().isInt({ min: 1 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const limit = parseInt(req.query.limit) || 6;
    const excludePropertyId = req.query.exclude ? parseInt(req.query.exclude) : null;

    const recommendations = await propertyService.getPropertyRecommendations(
      userId, 
      limit, 
      excludePropertyId
    );

    res.json({
      success: true,
      data: { recommendations }
    });
  })
);

// ================================================================
// PROPERTY CREATION ROUTES
// ================================================================

/**
 * Create new property listing
 * POST /api/properties
 */
router.post('/',
  createPropertyLimiter,
  authenticateToken,
  requireActiveAccount,
  createPropertyValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const ownerId = req.user.id;
    const propertyData = req.body;

    // Verify user can create properties (is_seller or admin/agent)
    if (!req.user.is_seller && req.user.user_type === 'user') {
      throw new AuthorizationError('You must be registered as a seller to list properties');
    }

    const property = await propertyService.createProperty(propertyData, ownerId);

    res.status(201).json({
      success: true,
      message: 'Property listing created successfully. It will be reviewed by our team before going live.',
      data: { property }
    });
  })
);

// ================================================================
// PROPERTY MANAGEMENT ROUTES (OWNER/ADMIN)
// ================================================================

/**
 * Get user's properties
 * GET /api/properties/my-properties
 */
router.get('/my-properties',
  authenticateToken,
  [
    query('status').optional().isIn(['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected']),
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const { status, page = 1, limit = 10 } = req.query;

    const filters = { owner_id: userId };
    if (status) filters.status = status;

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit)
    };

    const result = await propertyService.getProperties(filters, pagination);

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Update property
 * PUT /api/properties/:id
 */
router.put('/:id',
  updateLimiter,
  authenticateToken,
  requirePropertyOwnership,
  [param('id').isInt({ min: 1 }).withMessage('Valid property ID required')],
  updatePropertyValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const userId = req.user.id;
    const updates = req.body;

    const updatedProperty = await propertyService.updateProperty(propertyId, updates, userId);

    res.json({
      success: true,
      message: 'Property updated successfully',
      data: { property: updatedProperty }
    });
  })
);

/**
 * Delete property (soft delete)
 * DELETE /api/properties/:id
 */
router.delete('/:id',
  updateLimiter,
  authenticateToken,
  requirePropertyOwnership,
  [param('id').isInt({ min: 1 }).withMessage('Valid property ID required')],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const userId = req.user.id;

    await propertyService.deleteProperty(propertyId, userId);

    res.json({
      success: true,
      message: 'Property listing deleted successfully'
    });
  })
);

// ================================================================
// PROPERTY IMAGE ROUTES
// ================================================================

/**
 * Upload property images
 * POST /api/properties/:id/images
 */
router.post('/:id/images',
  updateLimiter,
  authenticateToken,
  requirePropertyOwnership,
  [param('id').isInt({ min: 1 }).withMessage('Valid property ID required')],
  handlePropertyImagesUpload,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const processedImages = req.processedImages;

    if (!processedImages || processedImages.length === 0) {
      throw new ValidationError('No images were processed');
    }

    const savedImages = await propertyService.addPropertyImages(propertyId, processedImages);

    res.status(201).json({
      success: true,
      message: `${savedImages.length} images uploaded successfully`,
      data: { images: savedImages }
    });
  })
);

/**
 * Update image order and details
 * PUT /api/properties/:id/images/order
 */
router.put('/:id/images/order',
  updateLimiter,
  authenticateToken,
  requirePropertyOwnership,
  [
    param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
    body('images').isArray({ min: 1 }).withMessage('Images array required'),
    body('images.*.id').isInt({ min: 1 }).withMessage('Valid image ID required'),
    body('images.*.display_order').isInt({ min: 0 }).withMessage('Valid display order required'),
    body('images.*.alt_text').optional().isLength({ max: 255 }).trim(),
    body('images.*.caption').optional().isLength({ max: 500 }).trim()
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const imageUpdates = req.body.images;

    await propertyService.updateImageOrder(propertyId, imageUpdates);

    res.json({
      success: true,
      message: 'Image order updated successfully'
    });
  })
);

/**
 * Delete property image
 * DELETE /api/properties/:id/images/:imageId
 */
router.delete('/:id/images/:imageId',
  updateLimiter,
  authenticateToken,
  requirePropertyOwnership,
  [
    param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
    param('imageId').isInt({ min: 1 }).withMessage('Valid image ID required')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const imageId = parseInt(req.params.imageId);

    await propertyService.removePropertyImage(propertyId, imageId);

    res.json({
      success: true,
      message: 'Image deleted successfully'
    });
  })
);

// ================================================================
// PROPERTY FAVORITES ROUTES
// ================================================================

/**
 * Toggle property favorite
 * POST /api/properties/:id/favorite
 */
router.post('/:id/favorite',
  authenticateToken,
  [
    param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
    body('notes').optional().isLength({ max: 500 }).trim().withMessage('Notes must be under 500 characters')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const userId = req.user.id;
    const { notes } = req.body;

    const result = await propertyService.togglePropertyFavorite(propertyId, userId, notes);

    res.json({
      success: true,
      message: `Property ${result.action} ${result.action === 'added' ? 'to' : 'from'} favorites`,
      data: result
    });
  })
);

/**
 * Get user's favorite properties
 * GET /api/properties/favorites
 */
router.get('/favorites',
  authenticateToken,
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 })
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const result = await propertyService.getUserFavorites(userId, { page, limit });

    res.json({
      success: true,
      data: result
    });
  })
);

// ================================================================
// PROPERTY ANALYTICS ROUTES
// ================================================================

/**
 * Get property analytics (owner/admin only)
 * GET /api/properties/:id/analytics
 */
router.get('/:id/analytics',
  authenticateToken,
  requirePropertyOwnership,
  [
    param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601()
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { date_from, date_to } = req.query;

    const dateRange = {};
    if (date_from) dateRange.date_from = date_from;
    if (date_to) dateRange.date_to = date_to;

    const analytics = await propertyService.getPropertyAnalytics(propertyId, dateRange);

    res.json({
      success: true,
      data: { analytics }
    });
  })
);

/**
 * Get property statistics for user
 * GET /api/properties/my-properties/stats
 */
router.get('/my-properties/stats',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const userType = req.user.user_type;

    const stats = await propertyService.getPropertyStats(userId, userType === 'agent' ? 'agent' : 'owner');

    res.json({
      success: true,
      data: { stats }
    });
  })
);

// ================================================================
// ADMIN PROPERTY ROUTES
// ================================================================

/**
 * Get all properties (admin)
 * GET /api/properties/admin/all
 */
router.get('/admin/all',
  authenticateToken,
  requireAdmin,
  searchValidation,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      search,
      property_type,
      city,
      status,
      owner_id,
      agent_id,
      page = 1,
      limit = 20
    } = req.query;

    const filters = {};
    if (search) filters.search = search;
    if (property_type) filters.property_type = Array.isArray(property_type) ? property_type : [property_type];
    if (city) filters.city = Array.isArray(city) ? city : [city];
    if (status) filters.status = status;
    if (owner_id) filters.owner_id = parseInt(owner_id);
    if (agent_id) filters.agent_id = parseInt(agent_id);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit)
    };

    const result = await propertyService.getProperties(filters, pagination);

    res.json({
      success: true,
      data: result
    });
  })
);

/**
 * Update property status (admin)
 * PUT /api/properties/admin/:id/status
 */
router.put('/admin/:id/status',
  updateLimiter,
  authenticateToken,
  requireAdmin,
  [
    param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
    body('status').isIn(['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected']).withMessage('Invalid status'),
    body('notes').optional().isLength({ max: 1000 }).trim().withMessage('Notes must be under 1000 characters')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const { status, notes } = req.body;
    const adminId = req.user.id;

    const updatedProperty = await propertyService.updatePropertyStatus(propertyId, status, adminId, notes);

    res.json({
      success: true,
      message: `Property status updated to ${status}`,
      data: { property: updatedProperty }
    });
  })
);

/**
 * Bulk status update (admin)
 * POST /api/properties/admin/bulk-status
 */
router.post('/admin/bulk-status',
  updateLimiter,
  authenticateToken,
  requireAdmin,
  [
    body('property_ids').isArray({ min: 1, max: 50 }).withMessage('Must provide 1-50 property IDs'),
    body('property_ids.*').isInt({ min: 1 }).withMessage('All property IDs must be valid integers'),
    body('status').isIn(['approved', 'active', 'rejected', 'withdrawn']).withMessage('Invalid status for bulk update'),
    body('notes').optional().isLength({ max: 500 }).trim().withMessage('Notes must be under 500 characters')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const { property_ids, status, notes } = req.body;
    const adminId = req.user.id;

    const results = [];
    const errors_list = [];

    for (const propertyId of property_ids) {
      try {
        const updatedProperty = await propertyService.updatePropertyStatus(propertyId, status, adminId, notes);
        results.push({
          property_id: propertyId,
          success: true,
          property: updatedProperty
        });
      } catch (error) {
        errors_list.push({
          property_id: propertyId,
          success: false,
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Bulk status update completed. ${results.length} successful, ${errors_list.length} failed.`,
      data: {
        successful: results,
        failed: errors_list,
        summary: {
          total: property_ids.length,
          successful: results.length,
          failed: errors_list.length
        }
      }
    });
  })
);

// ================================================================
// ADVANCED SEARCH ROUTES
// ================================================================

/**
 * Advanced property search
 * POST /api/properties/search
 */
router.post('/search',
  searchLimiter,
  optionalAuth,
  [
    body('query').optional().isLength({ max: 100 }).trim(),
    body('filters').optional().isObject(),
    body('location').optional().isObject(),
    body('location.latitude').optional().isFloat({ min: -90, max: 90 }),
    body('location.longitude').optional().isFloat({ min: -180, max: 180 }),
    body('location.radius_km').optional().isFloat({ min: 0.1, max: 100 }),
    body('sort').optional().isObject(),
    body('pagination').optional().isObject()
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      query: searchQuery,
      filters = {},
      location,
      sort = {},
      pagination = {}
    } = req.body;

    const searchParams = {
      q: searchQuery,
      ...filters,
      ...location,
      ...sort,
      page: pagination.page || 1,
      limit: pagination.limit || 12
    };

    const result = await propertyService.searchProperties(searchParams);

    res.json({
      success: true,
      data: result
    });
  })
);

// ================================================================
// PROPERTY VIEWS TRACKING
// ================================================================

/**
 * Track detailed property view
 * POST /api/properties/:id/view
 */
router.post('/:id/view',
  [
    param('id').isInt({ min: 1 }).withMessage('Valid property ID required'),
    body('time_spent_seconds').optional().isInt({ min: 1 }),
    body('scrolled_to_bottom').optional().isBoolean(),
    body('viewed_gallery').optional().isBoolean(),
    body('clicked_contact').optional().isBoolean()
  ],
  optionalAuth,
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const propertyId = parseInt(req.params.id);
    const userId = req.user?.id;
    const {
      time_spent_seconds,
      scrolled_to_bottom = false,
      viewed_gallery = false,
      clicked_contact = false
    } = req.body;

    const viewData = {
      user_id: userId,
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
      session_id: req.sessionID,
      referrer_url: req.get('Referer'),
      time_spent_seconds,
      scrolled_to_bottom,
      viewed_gallery,
      clicked_contact
    };

    await propertyService.recordPropertyView(propertyId, viewData);

    res.json({
      success: true,
      message: 'View recorded successfully'
    });
  })
);

// ================================================================
// EXPORT ROUTES
// ================================================================

/**
 * Export properties (admin)
 * GET /api/properties/admin/export
 */
router.get('/admin/export',
  authenticateToken,
  requireAdmin,
  [
    query('format').optional().isIn(['csv', 'json']).withMessage('Format must be csv or json'),
    query('status').optional().isIn(['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected']),
    query('city').optional().isArray(),
    query('property_type').optional().isArray(),
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601()
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError('Validation failed', errors.array());
    }

    const {
      format = 'csv',
      status,
      city,
      property_type,
      date_from,
      date_to
    } = req.query;

    const filters = {};
    if (status) filters.status = status;
    if (city) filters.city = Array.isArray(city) ? city : [city];
    if (property_type) filters.property_type = Array.isArray(property_type) ? property_type : [property_type];

    // Add date filters to search creation date
    if (date_from || date_to) {
      // This would need to be implemented in the service
      // filters.date_range = { from: date_from, to: date_to };
    }

    const result = await propertyService.getProperties(filters, { page: 1, limit: 10000 });

    if (format === 'json') {
      res.json({
        success: true,
        data: result.properties,
        exported_at: new Date().toISOString(),
        filters_applied: filters
      });
    } else {
      // CSV format
      const csvFields = [
        'listing_id', 'title', 'property_type', 'price', 'area', 'price_per_sqft',
        'city', 'location', 'bedrooms', 'bathrooms', 'parking', 'furnished',
        'status', 'owner_name', 'agent_name', 'views_count', 'favorites_count',
        'inquiries_count', 'created_at'
      ];

      let csvContent = csvFields.join(',') + '\n';
      
      result.properties.forEach(property => {
        const row = csvFields.map(field => {
          const value = property[field] || '';
          return `"${String(value).replace(/"/g, '""')}"`;
        }).join(',');
        csvContent += row + '\n';
      });

      const filename = `properties-export-${new Date().toISOString().split('T')[0]}.csv`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);
    }
  })
);

// ================================================================
// EXPORT ROUTER
// ================================================================

module.exports = router;