const path = require('path');
const fs = require('fs').promises;
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const morgan = require('morgan');
const multer = require('multer');
const pool = require('./middleware/db');
const { authenticateToken } = require('./middleware/authMiddleware');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 10000;

// Configuration Validation
const validateConfig = () => {
  const requiredVars = [
    'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
    'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
  ];
  const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');
  if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingVars);
    process.exit(1);
  }
  console.log('✅ Environment variables validated successfully');
  console.log('DEBUG: REDIS_URL:', process.env.REDIS_URL.replace(/:[^@]+@/, ':<redacted>@'));
};
validateConfig();

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);
    console.log(`DEBUG: Rate limiter IP: ${ip}, req.ip: ${req.ip}, X-Forwarded-For: ${req.headers['x-forwarded-for']}`);
    return ip;
  },
  validate: { ip: true },
  handler: (req, res) => {
    console.log(`DEBUG: Rate limit exceeded for ${req.method} ${req.originalUrl}`);
    res.status(429).json({
      error: 'Too many requests, please try again later.',
      retryAfter: Math.ceil(15 * 60)
    });
  }
});
app.use(limiter);

// Redis Client Setup
let sessionStore = new session.MemoryStore();
let redisErrorLogged = false;
const redisClient = createClient({
  url: process.env.REDIS_URL || `rediss://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`,
  password: process.env.REDIS_PASSWORD || undefined,
  socket: {
    tls: process.env.NODE_ENV === 'production',
    rejectUnauthorized: process.env.NODE_ENV !== 'production',
    reconnectStrategy: (retries) => {
      if (retries > 20) {
        console.error('❌ Max Redis retries reached');
        return new Error('Max retries reached');
      }
      const delay = Math.min(retries * 200, 5000);
      console.log(`DEBUG: Redis reconnect attempt ${retries + 1}, delay: ${delay}ms`);
      return delay;
    }
  }
});

redisClient.on('error', err => {
  console.error('❌ Redis Client Error:', err.message);
  if (!redisErrorLogged) {
    redisErrorLogged = true;
    sessionStore = new session.MemoryStore();
    console.warn('⚠️ Fallback to MemoryStore due to Redis failure');
  }
});

redisClient.on('connect', () => console.log('✅ Redis Client Connected'));
redisClient.on('ready', () => {
  console.log('✅ Redis Client Ready');
  sessionStore = new RedisStore({ client: redisClient });
  redisErrorLogged = false;
  console.log('Session store:', sessionStore instanceof RedisStore ? 'RedisStore' : 'MemoryStore');
});
redisClient.on('reconnecting', () => console.log('🔄 Attempting to reconnect to Redis...'));

// Session Middleware
app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET.trim(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = process.env.CORS_ORIGIN.split(',').map(o => o.trim());
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`DEBUG: CORS blocked for origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb', parameterLimit: 1000 }));
app.use(morgan('dev', {
  skip: false,
  stream: { write: (message) => console.log(`DEBUG: Morgan: ${message.trim()}`) }
}));
app.use(passport.initialize());
app.use(passport.session());

// File Upload Support
const uploadFolder = path.join(__dirname, 'Uploads');
const ensureUploadFolder = async () => {
  try {
    await fs.mkdir(uploadFolder, { recursive: true });
    console.log('✅ Upload folder ensured:', uploadFolder);
  } catch (err) {
    console.error('❌ Failed to create upload folder:', err.message);
  }
};
ensureUploadFolder();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

// Debug Middleware for /upload
app.use('/upload', authenticateToken, (req, res, next) => {
  console.log(`DEBUG: Incoming request to ${req.method} ${req.originalUrl}`);
  next();
});

// Supported datasets with their geometry types
const VALID_DATASETS = {
  buildings: 'MULTIPOLYGON',
  footpaths: 'LINESTRING',
  electricitySupply: 'LINESTRING',
  securityLights: 'POINT',
  roads: 'LINESTRING',
  drainageStructures: 'POINT',
  recreationalAreas: 'POLYGON',
  vimbweta: 'POLYGON',
  solidWasteCollection: 'POINT',
  parking: 'POLYGON',
  vegetation: 'POLYGON',
  aruboundary: 'POLYGON'
};

// Automatic table creation with PostGIS support
const initializeTables = async () => {
  const client = await pool.connect();
  try {
    await client.query('CREATE EXTENSION IF NOT EXISTS postgis');
    console.log('✅ PostGIS extension enabled');

    for (const [dataset, geomType] of Object.entries(VALID_DATASETS)) {
      const tableExists = await client.query(
        `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)`,
        [dataset]
      );

      if (!tableExists.rows[0].exists) {
        let createQuery;
        if (dataset === 'buildings') {
          createQuery = `
            CREATE TABLE buildings (
              id SERIAL PRIMARY KEY,
              geom GEOMETRY(MULTIPOLYGON, 4326),
              fid TEXT,
              building_id TEXT,
              name TEXT,
              floor TEXT,
              size TEXT,
              offices TEXT,
              use TEXT,
              conditions TEXT,
              created_at TIMESTAMP DEFAULT NOW(),
              updated_at TIMESTAMP DEFAULT NOW()
            )
          `;
        } else {
          createQuery = `
            CREATE TABLE "${dataset}" (
              id SERIAL PRIMARY KEY,
              geom GEOMETRY(${geomType}, 4326),
              properties JSONB,
              created_at TIMESTAMP DEFAULT NOW(),
              updated_at TIMESTAMP DEFAULT NOW()
            )
          `;
        }

        await client.query(createQuery);
        console.log(`✅ Created table ${dataset} with ${geomType} geometry type`);

        await client.query(`
          CREATE INDEX ${dataset}_geom_idx ON "${dataset}" USING GIST(geom)
        `);
        console.log(`✅ Created spatial index for ${dataset}`);
      }
    }
  } catch (err) {
    console.error('❌ Table initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
};

// Enhanced GeoJSON upload handler
app.post('/upload/:dataset', upload.single('file'), async (req, res, next) => {
  try {
    const { dataset } = req.params;
    
    if (!VALID_DATASETS[dataset]) {
      return res.status(400).json({ error: 'Invalid dataset type' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = path.join(uploadFolder, req.file.filename);
    const geojson = JSON.parse(await fs.readFile(filePath, 'utf8'));

    if (geojson.type !== 'FeatureCollection' || !Array.isArray(geojson.features)) {
      return res.status(400).json({ error: 'Invalid GeoJSON format' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      let insertedCount = 0;
      const errors = [];

      for (const feature of geojson.features) {
        try {
          if (!feature.geometry || !feature.geometry.type) {
            errors.push('Feature missing geometry');
            continue;
          }

          const expectedType = VALID_DATASETS[dataset];
          if (feature.geometry.type.toUpperCase() !== expectedType) {
            errors.push(`Expected ${expectedType} geometry, got ${feature.geometry.type}`);
            continue;
          }

          if (dataset === 'buildings') {
            const query = `
              INSERT INTO buildings (
                geom, fid, building_id, name, floor, size, offices, use, conditions
              ) VALUES (
                ST_SetSRID(ST_GeomFromGeoJSON($1), 4326),
                $2, $3, $4, $5, $6, $7, $8, $9
              )
            `;
            const properties = feature.properties || {};
            await client.query(query, [
              JSON.stringify(feature.geometry),
              properties.fid || null,
              properties.building_id || null,
              properties.name || null,
              properties.floor || null,
              properties.size || null,
              properties.offices || null,
              properties.use || null,
              properties.conditions || null
            ]);
          } else {
            const query = `
              INSERT INTO "${dataset}" (geom, properties)
              VALUES (ST_SetSRID(ST_GeomFromGeoJSON($1), 4326), $2)
            `;
            await client.query(query, [
              JSON.stringify(feature.geometry),
              JSON.stringify(feature.properties || {})
            ]);
          }
          insertedCount++;
        } catch (err) {
          errors.push(`Feature error: ${err.message}`);
          console.error('Error processing feature:', err);
        }
      }

      await client.query('COMMIT');
      await fs.unlink(filePath).catch(err => console.error('Error deleting file:', err));

      res.json({
        message: 'GeoJSON processed successfully',
        inserted: insertedCount,
        errors: errors.length > 0 ? errors : undefined,
        totalFeatures: geojson.features.length
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    next(err);
  }
});

// Enhanced GeoJSON retrieval
app.get('/api/:dataset', authenticateToken, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    
    if (!VALID_DATASETS[dataset]) {
      return res.status(400).json({ error: 'Invalid dataset type' });
    }

    const client = await pool.connect();
    try {
      const tableExists = await client.query(
        `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)`,
        [dataset]
      );
      
      if (!tableExists.rows[0].exists) {
        return res.status(404).json({ error: 'Dataset not found' });
      }

      let query;
      let result;
      
      if (dataset === 'buildings') {
        query = `
          SELECT 
            id,
            ST_AsGeoJSON(geom)::json AS geometry,
            fid, building_id, name, floor, size, offices, use, conditions
          FROM buildings
          WHERE ST_IsValid(geom)
        `;
        result = await client.query(query);
        
        const features = result.rows.map(row => ({
          type: 'Feature',
          id: row.id,
          geometry: row.geometry,
          properties: {
            fid: row.fid,
            building_id: row.building_id,
            name: row.name,
            floor: row.floor,
            size: row.size,
            offices: row.offices,
            use: row.use,
            conditions: row.conditions
          }
        }));
        
        return res.json({
          type: 'FeatureCollection',
          features
        });
      } else {
        query = `
          SELECT 
            id,
            ST_AsGeoJSON(geom)::json AS geometry,
            properties
          FROM "${dataset}"
          WHERE ST_IsValid(geom)
        `;
        result = await client.query(query);
        
        const features = result.rows.map(row => ({
          type: 'Feature',
          id: row.id,
          geometry: row.geometry,
          properties: row.properties
        }));
        
        return res.json({
          type: 'FeatureCollection',
          features
        });
      }
    } finally {
      client.release();
    }
  } catch (err) {
    next(err);
  }
});

// Dataset schema endpoint
app.get('/api/:dataset/schema', authenticateToken, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    
    if (!VALID_DATASETS[dataset]) {
      return res.status(400).json({ error: 'Invalid dataset type' });
    }

    const client = await pool.connect();
    try {
      const columnsRes = await client.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = $1
      `, [dataset]);

      const columns = columnsRes.rows
        .filter(row => !['id', 'geom', 'created_at', 'updated_at'].includes(row.column_name))
        .map(row => ({
          name: row.column_name,
          type: row.data_type
        }));

      res.json({ 
        dataset,
        geometryType: VALID_DATASETS[dataset],
        columns 
      });
    } finally {
      client.release();
    }
  } catch (err) {
    next(err);
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(`ERROR: Server Error [${req.method} ${req.originalUrl}]:`, err.message);
  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal Server Error occurred',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
});

// 404 Fallback
app.use((req, res) => {
  console.log(`DEBUG: 404 Route not found for ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: 'Route not found' });
});

// Test Database Connection
async function testDatabaseConnection() {
  try {
    // Test PostgreSQL connection
    const pgClient = await pool.connect();
    try {
      await pgClient.query('SELECT NOW()');
      console.log('✅ PostgreSQL connection successful');
    } finally {
      pgClient.release();
    }

    // Test Redis connection
    console.log('DEBUG: Redis client status:', redisClient.isOpen ? 'Open' : 'Closed');
    if (!redisClient.isOpen) {
      console.warn('⚠️ Redis client not open, attempting to reconnect...');
      await redisClient.connect();
    }
    await redisClient.ping();
    console.log('✅ Redis connection successful');
  } catch (err) {
    console.error('❌ Database connection test failed:', err.message);
    if (err.message.includes('Redis') || err.message.includes('client is closed')) {
      console.warn('⚠️ Falling back to MemoryStore due to Redis failure');
      sessionStore = new session.MemoryStore();
      redisErrorLogged = true;
    } else {
      throw err;
    }
  }
}

// Start Server
async function startServer() {
  try {
    await testDatabaseConnection();
    await initializeTables();
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log('Available datasets:', Object.keys(VALID_DATASETS));
    });
    server.on('error', (err) => {
      console.error('ERROR: Server startup failed:', err.message);
      process.exit(1);
    });
  } catch (err) {
    console.error('ERROR: Startup failed:', err.message);
    process.exit(1);
  }
}

startServer();