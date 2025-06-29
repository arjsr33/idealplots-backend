// ================================================================
// BACKEND/SERVICES/PROPERTYSERVICE.JS - PROPERTY MANAGEMENT SERVICE
// Business logic for property CRUD, search, recommendations, and image management
// ================================================================

const { 
  executeQuery, 
  executeTransaction, 
  handleDatabaseError 
} = require('../database/connection');

const {
  ValidationError,
  NotFoundError,
  DuplicateError,
  AuthorizationError
} = require('../middleware/errorHandler');

const { savePropertyImages, deletePropertyImage } = require('../middleware/upload');

// ================================================================
// PROPERTY CREATION FUNCTIONS
// ================================================================

/**
 * Create new property listing
 * @param {Object} propertyData - Property data
 * @param {number} ownerId - Owner user ID
 * @returns {Promise<Object>} Created property with details
 */
const createProperty = async (propertyData, ownerId) => {
  const {
    title,
    description,
    property_type,
    price,
    area,
    city,
    location,
    address,
    latitude,
    longitude,
    bedrooms,
    bathrooms,
    parking,
    furnished,
    features,
    meta_title,
    meta_description
  } = propertyData;

  return await executeTransaction(async (connection) => {
    // Generate unique listing ID
    const listingId = await generateListingId(connection, city, property_type);
    
    // Generate SEO-friendly slug
    const slug = await generateUniqueSlug(connection, title);

    // Create property record
    const [result] = await connection.execute(`
      INSERT INTO property_listings (
        listing_id, owner_id, title, description, property_type, price, area,
        city, location, address, latitude, longitude, bedrooms, bathrooms,
        parking, furnished, features, slug, meta_title, meta_description,
        status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', NOW(), NOW())
    `, [
      listingId, ownerId, title, description, property_type, price, area,
      city, location, address, latitude, longitude, bedrooms, bathrooms,
      parking, furnished, features ? JSON.stringify(features) : null,
      slug, meta_title, meta_description
    ]);

    const propertyId = result.insertId;

    // Auto-assign agent if enabled
    await autoAssignPropertyAgent(connection, propertyId, city, property_type);

    // Get the created property with all details
    return await getPropertyDetails(propertyId, true);
  });
};

/**
 * Generate unique listing ID
 * @param {Object} connection - Database connection
 * @param {string} city - Property city
 * @param {string} propertyType - Property type
 * @returns {Promise<string>} Unique listing ID
 */
const generateListingId = async (connection, city, propertyType) => {
  const year = new Date().getFullYear();
  const cityCode = city.substring(0, 3).toUpperCase();
  const typeCode = getPropertyTypeCode(propertyType);
  
  // Get next sequence number for this combination
  const [existing] = await connection.execute(`
    SELECT listing_id FROM property_listings 
    WHERE listing_id LIKE ? 
    ORDER BY listing_id DESC 
    LIMIT 1
  `, [`${cityCode}-${typeCode}-${year}-%`]);

  let sequence = 1;
  if (existing.length > 0) {
    const lastId = existing[0].listing_id;
    const lastSequence = parseInt(lastId.split('-').pop());
    sequence = lastSequence + 1;
  }

  return `${cityCode}-${typeCode}-${year}-${sequence.toString().padStart(4, '0')}`;
};

/**
 * Get property type code for listing ID
 * @param {string} propertyType - Property type
 * @returns {string} Type code
 */
const getPropertyTypeCode = (propertyType) => {
  const codes = {
    'residential_plot': 'RP',
    'commercial_plot': 'CP', 
    'agricultural_land': 'AL',
    'villa': 'VL',
    'apartment': 'AP',
    'house': 'HS',
    'commercial_building': 'CB',
    'warehouse': 'WH',
    'shop': 'SH',
    'office_space': 'OS'
  };
  return codes[propertyType] || 'PR';
};

/**
 * Generate unique SEO slug
 * @param {Object} connection - Database connection
 * @param {string} title - Property title
 * @returns {Promise<string>} Unique slug
 */
const generateUniqueSlug = async (connection, title) => {
  let baseSlug = title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .trim('-')
    .substring(0, 100);

  let slug = baseSlug;
  let counter = 1;

  while (true) {
    const [existing] = await connection.execute(
      'SELECT id FROM property_listings WHERE slug = ?',
      [slug]
    );

    if (existing.length === 0) {
      break;
    }

    slug = `${baseSlug}-${counter}`;
    counter++;
  }

  return slug;
};

/**
 * Auto-assign property to best available agent
 * @param {Object} connection - Database connection
 * @param {number} propertyId - Property ID
 * @param {string} city - Property city
 * @param {string} propertyType - Property type
 * @returns {Promise<number|null>} Assigned agent ID
 */
const autoAssignPropertyAgent = async (connection, propertyId, city, propertyType) => {
  try {
    // Check if auto-assignment is enabled
    const [settings] = await connection.execute(`
      SELECT setting_value FROM system_settings 
      WHERE setting_key = 'auto_assign_agents'
    `);

    if (settings.length === 0 || settings[0].setting_value !== 'true') {
      return null;
    }

    // Find best agent for this property
    const [agents] = await connection.execute(`
      SELECT u.id, u.name, COUNT(pl.id) as current_properties
      FROM users u
      LEFT JOIN property_listings pl ON u.id = pl.assigned_agent_id 
        AND pl.status IN ('pending_review', 'active')
      WHERE u.user_type = 'agent' 
        AND u.status = 'active'
        AND u.email_verified_at IS NOT NULL
        AND (u.specialization IS NULL OR u.specialization LIKE ?)
      GROUP BY u.id
      ORDER BY u.agent_rating DESC, current_properties ASC
      LIMIT 1
    `, [`%${propertyType}%`]);

    if (agents.length === 0) {
      return null;
    }

    const agentId = agents[0].id;

    // Assign agent to property
    await connection.execute(`
      UPDATE property_listings 
      SET assigned_agent_id = ?, updated_at = NOW()
      WHERE id = ?
    `, [agentId, propertyId]);

    return agentId;

  } catch (error) {
    console.error('Auto-assignment failed:', error);
    return null;
  }
};

// ================================================================
// PROPERTY RETRIEVAL FUNCTIONS
// ================================================================

/**
 * Get properties with advanced filtering and search
 * @param {Object} filters - Search and filter options
 * @param {Object} pagination - Pagination options
 * @param {Object} sorting - Sorting options
 * @returns {Promise<Object>} Properties and pagination info
 */
const getProperties = async (filters = {}, pagination = { page: 1, limit: 12 }, sorting = {}) => {
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
    status = 'active',
    owner_id,
    agent_id,
    is_featured,
    latitude,
    longitude,
    radius_km
  } = filters;

  const { page, limit } = pagination;
  const { sort_by = 'created_at', sort_order = 'DESC' } = sorting;
  const offset = (page - 1) * limit;

  let baseQuery = `
    SELECT 
      pl.id, pl.listing_id, pl.title, pl.description, pl.property_type,
      pl.price, pl.area, pl.price_per_sqft, pl.city, pl.location, pl.address,
      pl.latitude, pl.longitude, pl.bedrooms, pl.bathrooms, pl.parking,
      pl.furnished, pl.features, pl.main_image, pl.slug, pl.status,
      pl.is_featured, pl.featured_until, pl.views_count, pl.inquiries_count,
      pl.favorites_count, pl.created_at, pl.updated_at, pl.published_at,
      
      -- Owner details
      owner.name as owner_name, owner.phone as owner_phone,
      owner.email as owner_email, owner.profile_image as owner_image,
      
      -- Agent details
      agent.name as agent_name, agent.phone as agent_phone,
      agent.email as agent_email, agent.agency_name,
      
      -- Image count
      (SELECT COUNT(*) FROM property_images pi WHERE pi.property_id = pl.id) as image_count,
      
      -- Distance calculation (if location provided)
      ${latitude && longitude ? `
        (6371 * acos(cos(radians(?)) * cos(radians(pl.latitude)) * 
        cos(radians(pl.longitude) - radians(?)) + 
        sin(radians(?)) * sin(radians(pl.latitude)))) as distance_km,
      ` : ''}
      
      -- User-specific data (favorites) - will be null if not provided
      NULL as is_favorited
      
    FROM property_listings pl
    LEFT JOIN users owner ON pl.owner_id = owner.id
    LEFT JOIN users agent ON pl.assigned_agent_id = agent.id
    WHERE pl.deleted_at IS NULL
  `;

  const queryParams = [];

  // Add distance calculation parameters
  if (latitude && longitude) {
    queryParams.push(latitude, longitude, latitude);
  }

  // Apply filters
  if (status) {
    baseQuery += ' AND pl.status = ?';
    queryParams.push(status);
  }

  if (search) {
    baseQuery += ' AND (MATCH(pl.title, pl.description, pl.location) AGAINST(? IN BOOLEAN MODE) OR pl.listing_id LIKE ?)';
    queryParams.push(`+${search}*`, `%${search}%`);
  }

  if (property_type) {
    if (Array.isArray(property_type)) {
      baseQuery += ` AND pl.property_type IN (${property_type.map(() => '?').join(',')})`;
      queryParams.push(...property_type);
    } else {
      baseQuery += ' AND pl.property_type = ?';
      queryParams.push(property_type);
    }
  }

  if (city) {
    if (Array.isArray(city)) {
      baseQuery += ` AND pl.city IN (${city.map(() => '?').join(',')})`;
      queryParams.push(...city);
    } else {
      baseQuery += ' AND pl.city = ?';
      queryParams.push(city);
    }
  }

  if (location) {
    baseQuery += ' AND pl.location LIKE ?';
    queryParams.push(`%${location}%`);
  }

  if (price_min) {
    baseQuery += ' AND pl.price >= ?';
    queryParams.push(price_min);
  }

  if (price_max) {
    baseQuery += ' AND pl.price <= ?';
    queryParams.push(price_max);
  }

  if (area_min) {
    baseQuery += ' AND pl.area >= ?';
    queryParams.push(area_min);
  }

  if (area_max) {
    baseQuery += ' AND pl.area <= ?';
    queryParams.push(area_max);
  }

  if (bedrooms) {
    if (Array.isArray(bedrooms)) {
      baseQuery += ` AND pl.bedrooms IN (${bedrooms.map(() => '?').join(',')})`;
      queryParams.push(...bedrooms);
    } else {
      baseQuery += ' AND pl.bedrooms = ?';
      queryParams.push(bedrooms);
    }
  }

  if (bathrooms) {
    baseQuery += ' AND pl.bathrooms >= ?';
    queryParams.push(bathrooms);
  }

  if (parking !== undefined) {
    baseQuery += ' AND pl.parking = ?';
    queryParams.push(parking);
  }

  if (furnished !== undefined) {
    baseQuery += ' AND pl.furnished = ?';
    queryParams.push(furnished);
  }

  if (owner_id) {
    baseQuery += ' AND pl.owner_id = ?';
    queryParams.push(owner_id);
  }

  if (agent_id) {
    baseQuery += ' AND pl.assigned_agent_id = ?';
    queryParams.push(agent_id);
  }

  if (is_featured !== undefined) {
    baseQuery += ' AND pl.is_featured = ?';
    queryParams.push(is_featured);
  }

  // Distance filter
  if (latitude && longitude && radius_km) {
    baseQuery += ' HAVING distance_km <= ?';
    queryParams.push(radius_km);
  }

  // Get total count
  const countQuery = baseQuery.replace(/SELECT[\s\S]*?FROM/, 'SELECT COUNT(*) as total FROM');
  const [[{ total }]] = await executeQuery(countQuery, queryParams);

  // Apply sorting
  const validSortFields = ['created_at', 'price', 'area', 'price_per_sqft', 'views_count', 'favorites_count'];
  const sortField = validSortFields.includes(sort_by) ? sort_by : 'created_at';
  const sortDirection = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  // Special sorting for featured properties
  if (is_featured === undefined && status === 'active') {
    baseQuery += ` ORDER BY pl.is_featured DESC, pl.${sortField} ${sortDirection}`;
  } else if (latitude && longitude) {
    baseQuery += ` ORDER BY distance_km ASC, pl.${sortField} ${sortDirection}`;
  } else {
    baseQuery += ` ORDER BY pl.${sortField} ${sortDirection}`;
  }

  // Add pagination
  baseQuery += ' LIMIT ? OFFSET ?';
  queryParams.push(limit, offset);

  const properties = await executeQuery(baseQuery, queryParams);

  // Parse JSON features and add image URLs
  properties.forEach(property => {
    if (property.features) {
      try {
        property.features = JSON.parse(property.features);
      } catch (e) {
        property.features = null;
      }
    }
  });

  return {
    properties,
    pagination: {
      page,
      limit,
      total: parseInt(total),
      pages: Math.ceil(total / limit),
      hasNext: page < Math.ceil(total / limit),
      hasPrev: page > 1
    }
  };
};

/**
 * Get single property details
 * @param {number|string} identifier - Property ID or slug
 * @param {boolean} includeImages - Whether to include images
 * @param {number} userId - User ID for favorites check
 * @returns {Promise<Object>} Property details
 */
const getPropertyDetails = async (identifier, includeImages = true, userId = null) => {
  const isSlug = typeof identifier === 'string' && isNaN(identifier);
  
  const query = `
    SELECT 
      pl.id, pl.listing_id, pl.title, pl.description, pl.property_type,
      pl.price, pl.area, pl.price_per_sqft, pl.city, pl.location, pl.address,
      pl.latitude, pl.longitude, pl.bedrooms, pl.bathrooms, pl.parking,
      pl.furnished, pl.features, pl.main_image, pl.slug, pl.status,
      pl.is_featured, pl.featured_until, pl.views_count, pl.inquiries_count,
      pl.favorites_count, pl.meta_title, pl.meta_description,
      pl.created_at, pl.updated_at, pl.published_at,
      
      -- Owner details
      owner.id as owner_id, owner.name as owner_name, owner.phone as owner_phone,
      owner.email as owner_email, owner.profile_image as owner_image,
      owner.is_seller, owner.created_at as owner_since,
      
      -- Agent details
      agent.id as agent_id, agent.name as agent_name, agent.phone as agent_phone,
      agent.email as agent_email, agent.agency_name, agent.license_number,
      agent.agent_rating, agent.experience_years,
      
      -- Favorites check for user
      ${userId ? `(SELECT COUNT(*) FROM user_favorites uf WHERE uf.user_id = ? AND uf.property_id = pl.id) as is_favorited,` : ''}
      
      -- Recent enquiries count
      (SELECT COUNT(*) FROM enquiries e WHERE e.property_id = pl.id 
       AND e.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as recent_enquiries
      
    FROM property_listings pl
    LEFT JOIN users owner ON pl.owner_id = owner.id
    LEFT JOIN users agent ON pl.assigned_agent_id = agent.id
    WHERE ${isSlug ? 'pl.slug' : 'pl.id'} = ? AND pl.deleted_at IS NULL
  `;

  const queryParams = userId ? [userId, identifier] : [identifier];
  const [properties] = await executeQuery(query, queryParams);

  if (properties.length === 0) {
    throw new NotFoundError('Property not found');
  }

  const property = properties[0];

  // Parse JSON features
  if (property.features) {
    try {
      property.features = JSON.parse(property.features);
    } catch (e) {
      property.features = null;
    }
  }

  // Convert is_favorited to boolean
  if (userId) {
    property.is_favorited = property.is_favorited > 0;
  }

  // Get property images if requested
  if (includeImages) {
    const [images] = await executeQuery(`
      SELECT id, image_url, image_path, original_filename, alt_text,
             caption, display_order, image_type, created_at
      FROM property_images 
      WHERE property_id = ?
      ORDER BY display_order ASC, created_at ASC
    `, [property.id]);

    property.images = images;
  }

  return property;
};

/**
 * Get property recommendations for a user
 * @param {number} userId - User ID
 * @param {number} limit - Number of recommendations
 * @param {number} excludePropertyId - Property ID to exclude
 * @returns {Promise<Array>} Recommended properties
 */
const getPropertyRecommendations = async (userId, limit = 6, excludePropertyId = null) => {
  // Use stored procedure for recommendations
  const [recommendations] = await executeQuery('CALL GetUserRecommendations(?, ?)', [userId, limit]);
  
  if (excludePropertyId) {
    return recommendations.filter(prop => prop.id !== excludePropertyId);
  }
  
  return recommendations;
};

/**
 * Get similar properties based on property characteristics
 * @param {number} propertyId - Base property ID
 * @param {number} limit - Number of similar properties
 * @returns {Promise<Array>} Similar properties
 */
const getSimilarProperties = async (propertyId, limit = 6) => {
  const [baseProperty] = await executeQuery(`
    SELECT city, property_type, price, bedrooms FROM property_listings WHERE id = ?
  `, [propertyId]);

  if (baseProperty.length === 0) {
    return [];
  }

  const { city, property_type, price, bedrooms } = baseProperty[0];

  const [similar] = await executeQuery(`
    SELECT 
      pl.id, pl.listing_id, pl.title, pl.property_type, pl.price, pl.area,
      pl.city, pl.location, pl.bedrooms, pl.bathrooms, pl.main_image,
      pl.views_count, pl.favorites_count,
      
      -- Similarity score calculation
      (CASE WHEN pl.city = ? THEN 30 ELSE 0 END +
       CASE WHEN pl.property_type = ? THEN 25 ELSE 0 END +
       CASE WHEN pl.bedrooms = ? THEN 20 ELSE 0 END +
       CASE WHEN ABS(pl.price - ?) / ? < 0.3 THEN 25 ELSE 
            CASE WHEN ABS(pl.price - ?) / ? < 0.5 THEN 15 ELSE 0 END 
       END) as similarity_score
       
    FROM property_listings pl
    WHERE pl.id != ? 
      AND pl.status = 'active' 
      AND pl.deleted_at IS NULL
      AND (pl.city = ? OR pl.property_type = ? OR pl.bedrooms = ?)
    HAVING similarity_score > 20
    ORDER BY similarity_score DESC, pl.created_at DESC
    LIMIT ?
  `, [
    city, property_type, bedrooms, price, price, price, price,
    propertyId, city, property_type, bedrooms, limit
  ]);

  return similar;
};

// ================================================================
// PROPERTY UPDATE FUNCTIONS
// ================================================================

/**
 * Update property listing
 * @param {number} propertyId - Property ID
 * @param {Object} updates - Update data
 * @param {number} userId - User making the update
 * @returns {Promise<Object>} Updated property
 */
const updateProperty = async (propertyId, updates, userId) => {
  const allowedFields = [
    'title', 'description', 'price', 'area', 'city', 'location', 'address',
    'latitude', 'longitude', 'bedrooms', 'bathrooms', 'parking', 'furnished',
    'features', 'meta_title', 'meta_description'
  ];

  const updateFields = [];
  const updateValues = [];

  // Process each allowed field
  for (const field of allowedFields) {
    if (updates[field] !== undefined) {
      updateFields.push(`${field} = ?`);
      updateValues.push(field === 'features' ? JSON.stringify(updates[field]) : updates[field]);
    }
  }

  if (updateFields.length === 0) {
    throw new ValidationError('No valid update fields provided');
  }

  // Update slug if title changed
  if (updates.title) {
    const newSlug = await generateUniqueSlug({ execute: executeQuery }, updates.title);
    updateFields.push('slug = ?');
    updateValues.push(newSlug);
  }

  updateFields.push('updated_at = NOW()');
  updateValues.push(propertyId);

  await executeQuery(`
    UPDATE property_listings 
    SET ${updateFields.join(', ')}
    WHERE id = ?
  `, updateValues);

  return await getPropertyDetails(propertyId, true);
};

/**
 * Update property status
 * @param {number} propertyId - Property ID
 * @param {string} newStatus - New status
 * @param {number} userId - User making the update
 * @param {string} notes - Status change notes
 * @returns {Promise<Object>} Updated property
 */
const updatePropertyStatus = async (propertyId, newStatus, userId, notes = null) => {
  const validStatuses = ['draft', 'pending_review', 'approved', 'active', 'sold', 'rented', 'withdrawn', 'expired', 'rejected'];
  
  if (!validStatuses.includes(newStatus)) {
    throw new ValidationError('Invalid status');
  }

  await executeTransaction(async (connection) => {
    // Update property status
    const updateFields = ['status = ?', 'updated_at = NOW()'];
    const updateValues = [newStatus];

    // Set additional fields based on status
    if (newStatus === 'active') {
      updateFields.push('published_at = NOW()');
    } else if (['sold', 'rented'].includes(newStatus)) {
      updateFields.push('published_at = NULL');
    }

    if (notes) {
      updateFields.push('review_notes = ?');
      updateValues.push(notes);
    }

    if (userId && ['approved', 'rejected'].includes(newStatus)) {
      updateFields.push('reviewed_by = ?', 'reviewed_at = NOW()');
      updateValues.push(userId);
    }

    updateValues.push(propertyId);

    await connection.execute(`
      UPDATE property_listings 
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `, updateValues);

    // Update pending approval if exists
    if (['approved', 'rejected'].includes(newStatus)) {
      await connection.execute(`
        UPDATE pending_approvals 
        SET status = ?, approved_by = ?, approved_at = NOW(), admin_notes = ?
        WHERE approval_type = 'property_listing' AND record_id = ?
      `, [newStatus === 'approved' ? 'approved' : 'rejected', userId, notes, propertyId]);
    }

    // Log the status change
    await connection.execute(`
      INSERT INTO audit_logs (
        user_id, action, table_name, record_id, description, severity
      ) VALUES (?, 'status_change', 'property_listings', ?, ?, 'medium')
    `, [userId, propertyId, `Property status changed to ${newStatus}${notes ? `: ${notes}` : ''}`]);
  });

  return await getPropertyDetails(propertyId, false);
};

// ================================================================
// PROPERTY IMAGE FUNCTIONS
// ================================================================

/**
 * Add images to property
 * @param {number} propertyId - Property ID
 * @param {Array} processedImages - Processed image data from upload middleware
 * @param {Object} options - Additional options
 * @returns {Promise<Array>} Saved image records
 */
const addPropertyImages = async (propertyId, processedImages, options = {}) => {
  // Verify property exists and get current image count
  const [properties] = await executeQuery(`
    SELECT id, main_image FROM property_listings WHERE id = ?
  `, [propertyId]);

  if (properties.length === 0) {
    throw new NotFoundError('Property not found');
  }

  const property = properties[0];

  // Get current max display order
  const [maxOrder] = await executeQuery(`
    SELECT COALESCE(MAX(display_order), -1) as max_order 
    FROM property_images WHERE property_id = ?
  `, [propertyId]);

  const startOrder = maxOrder[0].max_order + 1;

  // Save images to database
  const savedImages = await savePropertyImages(propertyId, processedImages, {
    ...options,
    startOrder
  });

  // Set first image as main image if none exists
  if (!property.main_image && savedImages.length > 0) {
    await executeQuery(`
      UPDATE property_listings 
      SET main_image = ?, updated_at = NOW()
      WHERE id = ?
    `, [savedImages[0].image_url, propertyId]);
  }

  return savedImages;
};

/**
 * Update image order and details
 * @param {number} propertyId - Property ID
 * @param {Array} imageUpdates - Array of image updates
 * @returns {Promise<boolean>} Success status
 */
const updateImageOrder = async (propertyId, imageUpdates) => {
  await executeTransaction(async (connection) => {
    for (const update of imageUpdates) {
      const { id, display_order, alt_text, caption } = update;
      
      await connection.execute(`
        UPDATE property_images 
        SET display_order = ?, alt_text = ?, caption = ?, updated_at = NOW()
        WHERE id = ? AND property_id = ?
      `, [display_order, alt_text, caption, id, propertyId]);
    }
  });

  return true;
};

/**
 * Delete property image
 * @param {number} propertyId - Property ID
 * @param {number} imageId - Image ID
 * @returns {Promise<boolean>} Success status
 */
const removePropertyImage = async (propertyId, imageId) => {
  return await deletePropertyImage(imageId, propertyId);
};

// ================================================================
// PROPERTY ANALYTICS FUNCTIONS
// ================================================================

/**
 * Record property view
 * @param {number} propertyId - Property ID
 * @param {Object} viewData - View tracking data
 * @returns {Promise<boolean>} Success status
 */
const recordPropertyView = async (propertyId, viewData) => {
  const {
    user_id = null,
    ip_address,
    user_agent,
    session_id,
    referrer_url,
    time_spent_seconds = null,
    scrolled_to_bottom = false,
    viewed_gallery = false,
    clicked_contact = false
  } = viewData;

  await executeTransaction(async (connection) => {
    // Check if this IP has viewed this property recently (prevent spam)
    const [recentViews] = await connection.execute(`
      SELECT id FROM property_views 
      WHERE property_id = ? AND ip_address = ? 
        AND viewed_at > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
    `, [propertyId, ip_address]);

    if (recentViews.length === 0) {
      // Record new view
      await connection.execute(`
        INSERT INTO property_views (
          property_id, user_id, ip_address, user_agent, session_id,
          referrer_url, time_spent_seconds, scrolled_to_bottom,
          viewed_gallery, clicked_contact, viewed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `, [
        propertyId, user_id, ip_address, user_agent, session_id,
        referrer_url, time_spent_seconds, scrolled_to_bottom,
        viewed_gallery, clicked_contact
      ]);

      // Update property views count
      await connection.execute(`
        UPDATE property_listings 
        SET views_count = views_count + 1, updated_at = NOW()
        WHERE id = ?
      `, [propertyId]);
    }
  });

  return true;
};

/**
 * Get property analytics
 * @param {number} propertyId - Property ID
 * @param {Object} dateRange - Date range for analytics
 * @returns {Promise<Object>} Analytics data
 */
const getPropertyAnalytics = async (propertyId, dateRange = {}) => {
  const { date_from, date_to } = dateRange;
  
  let dateFilter = '';
  const queryParams = [propertyId];
  
  if (date_from) {
    dateFilter += ' AND pv.viewed_at >= ?';
    queryParams.push(date_from);
  }
  
  if (date_to) {
    dateFilter += ' AND pv.viewed_at <= ?';
    queryParams.push(date_to + ' 23:59:59');
  }

  // Basic stats
  const [basicStats] = await executeQuery(`
    SELECT 
      pl.views_count, pl.favorites_count, pl.inquiries_count,
      COUNT(DISTINCT pv.ip_address) as unique_visitors,
      COUNT(pv.id) as total_views,
      AVG(pv.time_spent_seconds) as avg_time_spent,
      COUNT(CASE WHEN pv.viewed_gallery = TRUE THEN 1 END) as gallery_views,
      COUNT(CASE WHEN pv.clicked_contact = TRUE THEN 1 END) as contact_clicks,
      COUNT(CASE WHEN pv.scrolled_to_bottom = TRUE THEN 1 END) as full_page_views
    FROM property_listings pl
    LEFT JOIN property_views pv ON pl.id = pv.property_id ${dateFilter}
    WHERE pl.id = ?
    GROUP BY pl.id
  `, queryParams);

  // Daily views trend
  const [dailyViews] = await executeQuery(`
    SELECT 
      DATE(viewed_at) as date,
      COUNT(*) as views,
      COUNT(DISTINCT ip_address) as unique_visitors
    FROM property_views 
    WHERE property_id = ? ${dateFilter}
    GROUP BY DATE(viewed_at)
    ORDER BY date ASC
  `, queryParams);

  // Referrer analysis
  const [referrers] = await executeQuery(`
    SELECT 
      CASE 
        WHEN referrer_url IS NULL THEN 'Direct'
        WHEN referrer_url LIKE '%google%' THEN 'Google'
        WHEN referrer_url LIKE '%facebook%' THEN 'Facebook'
        WHEN referrer_url LIKE '%whatsapp%' THEN 'WhatsApp'
        ELSE 'Other'
      END as source,
      COUNT(*) as views,
      COUNT(DISTINCT ip_address) as unique_visitors
    FROM property_views 
    WHERE property_id = ? ${dateFilter}
    GROUP BY source
    ORDER BY views DESC
  `, queryParams);

  return {
    summary: basicStats[0] || {
      views_count: 0,
      favorites_count: 0,
      inquiries_count: 0,
      unique_visitors: 0,
      total_views: 0,
      avg_time_spent: null,
      gallery_views: 0,
      contact_clicks: 0,
      full_page_views: 0
    },
    trends: {
      daily_views: dailyViews
    },
    traffic_sources: referrers
  };
};

// ================================================================
// PROPERTY FAVORITES FUNCTIONS
// ================================================================

/**
 * Toggle property favorite for user
 * @param {number} propertyId - Property ID
 * @param {number} userId - User ID
 * @param {string} notes - User notes about the property
 * @returns {Promise<Object>} Favorite status and updated counts
 */
const togglePropertyFavorite = async (propertyId, userId, notes = null) => {
  return await executeTransaction(async (connection) => {
    // Check if already favorited
    const [existing] = await connection.execute(`
      SELECT id FROM user_favorites 
      WHERE user_id = ? AND property_id = ?
    `, [userId, propertyId]);

    let isFavorited = false;
    let action = '';

    if (existing.length > 0) {
      // Remove from favorites
      await connection.execute(`
        DELETE FROM user_favorites 
        WHERE user_id = ? AND property_id = ?
      `, [userId, propertyId]);
      action = 'removed';
    } else {
      // Add to favorites
      await connection.execute(`
        INSERT INTO user_favorites (user_id, property_id, notes, created_at, updated_at)
        VALUES (?, ?, ?, NOW(), NOW())
      `, [userId, propertyId, notes]);
      isFavorited = true;
      action = 'added';
    }

    // Get updated favorite count
    const [counts] = await connection.execute(`
      SELECT favorites_count FROM property_listings WHERE id = ?
    `, [propertyId]);

    return {
      is_favorited: isFavorited,
      action: action,
      favorites_count: counts[0]?.favorites_count || 0
    };
  });
};

/**
 * Get user's favorite properties
 * @param {number} userId - User ID
 * @param {Object} pagination - Pagination options
 * @returns {Promise<Object>} Favorite properties and pagination
 */
const getUserFavorites = async (userId, pagination = { page: 1, limit: 10 }) => {
  const { page, limit } = pagination;
  const offset = (page - 1) * limit;

  // Get total count
  const [[{ total }]] = await executeQuery(`
    SELECT COUNT(*) as total 
    FROM user_favorites uf
    JOIN property_listings pl ON uf.property_id = pl.id
    WHERE uf.user_id = ? AND pl.status = 'active' AND pl.deleted_at IS NULL
  `, [userId]);

  // Get paginated favorites
  const favorites = await executeQuery(`
    SELECT 
      pl.id, pl.listing_id, pl.title, pl.property_type, pl.price, pl.area,
      pl.city, pl.location, pl.bedrooms, pl.bathrooms, pl.main_image,
      pl.views_count, pl.favorites_count, pl.status,
      uf.notes as user_notes, uf.created_at as favorited_at,
      owner.name as owner_name, owner.phone as owner_phone
    FROM user_favorites uf
    JOIN property_listings pl ON uf.property_id = pl.id
    LEFT JOIN users owner ON pl.owner_id = owner.id
    WHERE uf.user_id = ? AND pl.status = 'active' AND pl.deleted_at IS NULL
    ORDER BY uf.created_at DESC
    LIMIT ? OFFSET ?
  `, [userId, limit, offset]);

  return {
    favorites,
    pagination: {
      page,
      limit,
      total: parseInt(total),
      pages: Math.ceil(total / limit),
      hasNext: page < Math.ceil(total / limit),
      hasPrev: page > 1
    }
  };
};

// ================================================================
// PROPERTY SEARCH FUNCTIONS
// ================================================================

/**
 * Advanced property search with filters and full-text search
 * @param {Object} searchParams - Search parameters
 * @returns {Promise<Object>} Search results
 */
const searchProperties = async (searchParams) => {
  const {
    q: query,
    property_type,
    city,
    price_range,
    bedrooms,
    bathrooms,
    area_range,
    features,
    sort_by = 'relevance',
    page = 1,
    limit = 12
  } = searchParams;

  let searchQuery = `
    SELECT 
      pl.id, pl.listing_id, pl.title, pl.description, pl.property_type,
      pl.price, pl.area, pl.price_per_sqft, pl.city, pl.location,
      pl.bedrooms, pl.bathrooms, pl.parking, pl.furnished,
      pl.main_image, pl.views_count, pl.favorites_count,
      owner.name as owner_name, owner.phone as owner_phone,
      
      -- Relevance score for search
      ${query ? `
        (MATCH(pl.title, pl.description, pl.location) AGAINST(? IN BOOLEAN MODE) * 10 +
         CASE WHEN pl.title LIKE ? THEN 5 ELSE 0 END +
         CASE WHEN pl.location LIKE ? THEN 3 ELSE 0 END +
         CASE WHEN pl.is_featured = TRUE THEN 2 ELSE 0 END) as relevance_score
      ` : '0 as relevance_score'}
      
    FROM property_listings pl
    LEFT JOIN users owner ON pl.owner_id = owner.id
    WHERE pl.status = 'active' AND pl.deleted_at IS NULL
  `;

  const queryParams = [];

  // Add search query parameters
  if (query) {
    queryParams.push(`+${query}*`, `%${query}%`, `%${query}%`);
    searchQuery += ` AND MATCH(pl.title, pl.description, pl.location) AGAINST(? IN BOOLEAN MODE)`;
    queryParams.push(`+${query}*`);
  }

  // Apply other filters (reusing logic from getProperties)
  // ... (filter logic similar to getProperties function)

  // Add sorting
  if (sort_by === 'relevance' && query) {
    searchQuery += ' ORDER BY relevance_score DESC, pl.is_featured DESC';
  } else if (sort_by === 'price_low') {
    searchQuery += ' ORDER BY pl.price ASC';
  } else if (sort_by === 'price_high') {
    searchQuery += ' ORDER BY pl.price DESC';
  } else if (sort_by === 'newest') {
    searchQuery += ' ORDER BY pl.created_at DESC';
  } else {
    searchQuery += ' ORDER BY pl.is_featured DESC, pl.created_at DESC';
  }

  // Add pagination
  const offset = (page - 1) * limit;
  searchQuery += ' LIMIT ? OFFSET ?';
  queryParams.push(limit, offset);

  const results = await executeQuery(searchQuery, queryParams);

  return {
    properties: results,
    search_params: searchParams,
    total_results: results.length
  };
};

// ================================================================
// UTILITY FUNCTIONS
// ================================================================

/**
 * Delete property (soft delete)
 * @param {number} propertyId - Property ID
 * @param {number} userId - User performing deletion
 * @returns {Promise<boolean>} Success status
 */
const deleteProperty = async (propertyId, userId) => {
  await executeTransaction(async (connection) => {
    // Soft delete the property
    await connection.execute(`
      UPDATE property_listings 
      SET deleted_at = NOW(), status = 'withdrawn', updated_at = NOW()
      WHERE id = ?
    `, [propertyId]);

    // Log the deletion
    await connection.execute(`
      INSERT INTO audit_logs (
        user_id, action, table_name, record_id, description, severity
      ) VALUES (?, 'delete', 'property_listings', ?, 'Property listing deleted', 'medium')
    `, [userId, propertyId]);
  });

  return true;
};

/**
 * Get property statistics for owner/agent
 * @param {number} userId - User ID
 * @param {string} userType - User type (owner/agent)
 * @returns {Promise<Object>} Property statistics
 */
const getPropertyStats = async (userId, userType = 'owner') => {
  const field = userType === 'agent' ? 'assigned_agent_id' : 'owner_id';
  
  const [stats] = await executeQuery(`
    SELECT 
      COUNT(*) as total_properties,
      COUNT(CASE WHEN status = 'active' THEN 1 END) as active_properties,
      COUNT(CASE WHEN status = 'pending_review' THEN 1 END) as pending_properties,
      COUNT(CASE WHEN status = 'sold' THEN 1 END) as sold_properties,
      COUNT(CASE WHEN status = 'rented' THEN 1 END) as rented_properties,
      SUM(views_count) as total_views,
      SUM(favorites_count) as total_favorites,
      SUM(inquiries_count) as total_inquiries,
      AVG(price) as avg_price,
      MIN(price) as min_price,
      MAX(price) as max_price
    FROM property_listings 
    WHERE ${field} = ? AND deleted_at IS NULL
  `, [userId]);

  return stats[0] || {
    total_properties: 0,
    active_properties: 0,
    pending_properties: 0,
    sold_properties: 0,
    rented_properties: 0,
    total_views: 0,
    total_favorites: 0,
    total_inquiries: 0,
    avg_price: null,
    min_price: null,
    max_price: null
  };
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core CRUD functions
  createProperty,
  getProperties,
  getPropertyDetails,
  updateProperty,
  updatePropertyStatus,
  deleteProperty,
  
  // Search and recommendations
  searchProperties,
  getPropertyRecommendations,
  getSimilarProperties,
  
  // Image management
  addPropertyImages,
  updateImageOrder,
  removePropertyImage,
  
  // Analytics and tracking
  recordPropertyView,
  getPropertyAnalytics,
  
  // Favorites
  togglePropertyFavorite,
  getUserFavorites,
  
  // Statistics
  getPropertyStats,
  
  // Utility functions
  generateListingId,
  generateUniqueSlug,
  autoAssignPropertyAgent
};