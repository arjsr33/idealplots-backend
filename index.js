// ================================================================
// BACKEND/INDEX.JS - MAIN ENTRY POINT
// Real Estate Platform Backend Server
// ================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const dotenv = require('dotenv');
const path = require('path');

// 🔄 CHANGE 1: Smart environment loading
const envFile = process.env.NODE_ENV === 'production' 
  ? '.env.production' 
  : '.env.development';
dotenv.config({ path: envFile });

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const { authenticateToken } = require('./middleware/auth');

// Import route modules
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');
const agentRoutes = require('./routes/agents');
const propertyRoutes = require('./routes/properties');
const enquiryRoutes = require('./routes/enquiries');

// Initialize Express app
const app = express();

// 🔄 CHANGE 2: Trust proxy for production (Hostinger)
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// ================================================================
// SECURITY & MIDDLEWARE CONFIGURATION
// ================================================================

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'https://idealplots.in'
    ];
    
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// Request parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression
app.use(compression());

// Logging
const logFormat = process.env.NODE_ENV === 'production' ? 'combined' : 'dev';
app.use(morgan(logFormat));

// ================================================================
// RATE LIMITING
// ================================================================

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Auth-specific rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Admin-specific rate limiting
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit admin operations
  message: {
    error: 'Too many admin requests, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply general rate limiting to all requests
app.use(generalLimiter);

// ================================================================
// HEALTH CHECK & MONITORING
// ================================================================

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.APP_VERSION || '1.0.0'
  });
});

// Database health check
app.get('/health/db', async (req, res) => {
  try {
    // 🔄 CHANGE 3: Updated database connection import
    const { testConnection } = require('./database/connection');
    const isConnected = await testConnection();
    
    if (isConnected) {
      res.status(200).json({
        status: 'healthy',
        database: 'connected',
        timestamp: new Date().toISOString()
      });
    } else {
      throw new Error('Database connection failed');
    }
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// ================================================================
// API ROUTES
// ================================================================

// Public routes (no authentication required)
app.use('/api/auth', authLimiter, authRoutes);

// Protected routes (authentication required)
app.use('/api/users', authenticateToken, userRoutes);
app.use('/api/properties', propertyRoutes); // Some endpoints public, some protected
app.use('/api/enquiries', enquiryRoutes); // Some endpoints public, some protected

// Role-based protected routes
app.use('/api/admin', authenticateToken, adminLimiter, adminRoutes);
app.use('/api/agents', authenticateToken, agentRoutes);

// ================================================================
// STATIC FILE SERVING (ENVIRONMENT AWARE)
// ================================================================

// 🔄 CHANGE 4: Smart upload path based on environment
const uploadsPath = process.env.NODE_ENV === 'production'
  ? '/home/username/public_html/uploads'  // Hostinger path
  : path.join(__dirname, 'uploads');      // Development path

// Serve uploaded files (with proper security)
app.use('/uploads', express.static(uploadsPath, {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    // Security headers for file serving
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    
    // Only allow specific file types
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx'];
    const ext = path.extname(filePath).toLowerCase();
    
    if (!allowedExtensions.includes(ext)) {
      res.status(403).end();
      return;
    }
  }
}));

// ================================================================
// ERROR HANDLING
// ================================================================

// 404 handler for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use(errorHandler);

// ================================================================
// GRACEFUL SHUTDOWN
// ================================================================

const gracefulShutdown = (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  server.close(() => {
    console.log('HTTP server closed.');
    
    // 🔄 CHANGE 5: Updated database connection import
    const { closeAllConnections } = require('./database/connection');
    closeAllConnections()
      .then(() => {
        console.log('Database connections closed.');
        process.exit(0);
      })
      .catch((error) => {
        console.error('Error closing database connections:', error);
        process.exit(1);
      });
  });
  
  // Force shutdown after 30 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

// ================================================================
// SERVER STARTUP
// ================================================================

// Updated default port for Hostinger
const PORT = process.env.PORT || 3000;  // Changed from 5000 to 3000
const HOST = process.env.HOST || '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                    REAL ESTATE BACKEND                        ║
║                   ${(process.env.NODE_ENV || 'development').toUpperCase()} MODE                           ║
╠════════════════════════════════════════════════════════════════╣
║ Environment: ${(process.env.NODE_ENV || 'development').padEnd(44)} ║
║ Server URL:  http://${HOST}:${PORT}${' '.repeat(31 - HOST.length - PORT.toString().length)} ║
║ Health URL:  http://${HOST}:${PORT}/health${' '.repeat(23 - HOST.length - PORT.toString().length)} ║
║ API Base:    http://${HOST}:${PORT}/api${' '.repeat(26 - HOST.length - PORT.toString().length)} ║
║ Upload Path: ${uploadsPath.substring(0, 44).padEnd(44)} ║
╚════════════════════════════════════════════════════════════════╝
  `);
  
  // Test database connection on startup
  const { testConnection } = require('./database/connection');
  testConnection()
    .then((isConnected) => {
      if (isConnected) {
        console.log('✅ Database connection successful');
      } else {
        console.error('❌ Database connection failed');
      }
    })
    .catch((error) => {
      console.error('❌ Database connection error:', error.message);
    });
});

// Handle graceful shutdown
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});

// Export app for testing
module.exports = app;