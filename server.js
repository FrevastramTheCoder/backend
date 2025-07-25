const path = require('path');
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
const { rateLimit } = require('express-rate-limit');
const morgan = require('morgan');
const multer = require('multer');
const fs = require('fs').promises;
const pool = require('./middleware/db');
const { authenticateToken } = require('./middleware/authMiddleware');
let geojsonUpload;
try {
  geojsonUpload = require('./routes/geojson');
  console.log('DEBUG: geojsonUpload router loaded successfully');
} catch (err) {
  console.error('❌ Failed to load geojsonUpload router:', err.stack);
  geojsonUpload = express.Router(); // Fallback to empty router
}

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
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = req.ip || (req.headers['x-forwarded-for']?.split(',').shift()?.trim() || 'unknown');
    console.log(`DEBUG: Rate limiter IP: ${ip}`, `req.ip: ${req.ip}`, `X-Forwarded-For: ${req.headers['x-forwarded-for']}`);
    return ip;
  },
  validate: { ip: true },
  handler: (req, res) => {
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
  url: process.env.REDIS_URL || `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`,
  socket: {
    tls: process.env.NODE_ENV === 'production',
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        console.error('❌ Max Redis retries reached');
        return new Error('Max retries reached');
      }
      return Math.min(retries * 100, 3000);
    }
  }
});

redisClient.on('error', err => {
  console.error('❌ Redis Client Error:', err.stack);
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
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
app.use(morgan('dev'));
app.use(passport.initialize());
app.use(passport.session());

// File Upload Support
const uploadFolder = path.join(__dirname, 'uploads');
const ensureUploadFolder = async () => {
  try {
    await fs.mkdir(uploadFolder, { recursive: true });
    console.log('✅ Upload folder ensured:', uploadFolder);
  } catch (err) {
    console.error('❌ Failed to create upload folder:', err.stack);
  }
};
ensureUploadFolder();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

// Direct Upload Route for Buildings
app.post('/upload/buildings', upload.single('file'), async (req, res, next) => {
  console.log(`DEBUG: Handling POST /upload/buildings`);
  try {
    if (!req.file) {
      console.log('ERROR: No file uploaded');
      return res.status(400).json({ error: 'No file uploaded' });
    }
    console.log('DEBUG: Uploaded file:', req.file.originalname);
    res.json({
      message: 'Building GeoJSON uploaded successfully',
      filename: req.file.originalname,
    });
  } catch (err) {
    console.error('ERROR: Upload failed:', err.stack);
    next(err);
  }
});

// Initialize Database Tables
const VALID_DATASETS = [
  'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
  'drainageStructures', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
  'parking', 'vegetation', 'aruboundary'
];

const initializeTables = async () => {
  const client = await pool.connect();
  try {
    const postgisCheck = await client.query("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis')");
    if (!postgisCheck.rows[0].exists) {
      await client.query('CREATE EXTENSION IF NOT EXISTS postgis');
      console.log('✅ PostGIS extension enabled');
    }
    for (const dataset of VALID_DATASETS) {
      const tableExists = await client.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = $1
        )
      `, [dataset]);
      if (!tableExists.rows[0].exists) {
        let createQuery = `
          CREATE TABLE "${dataset}" (
            id SERIAL PRIMARY KEY,
            geom GEOMETRY NOT NULL
          )
        `;
        if (dataset === 'buildings') {
          createQuery = `
            CREATE TABLE "${dataset}" (
              id SERIAL PRIMARY KEY,
              geom GEOMETRY(MULTIPOLYGON, 4326) NOT NULL,
              fid FLOAT,
              building_id FLOAT,
              name TEXT,
              floor TEXT,
              size FLOAT,
              offices TEXT,
              use TEXT,
              conditions TEXT
            )
          `;
        }
        await client.query(createQuery);
        await client.query(`
          SELECT UpdateGeometrySRID('${dataset}', 'geom', 4326)
        `);
        console.log(`✅ Created table ${dataset} with schema`);
      }
    }
    console.log('✅ All dataset tables initialized');
  } catch (err) {
    console.error('❌ Table initialization failed:', err.stack);
    throw err;
  } finally {
    client.release();
  }
};

// Sanitize column names to be SQL-safe
function sanitizeColumnName(name) {
  const RESERVED_KEYWORDS = ['select', 'from', 'where', 'table', 'index', 'group', 'order'];
  let sanitized = name
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/^(\d)/, '_$1')
    .toLowerCase()
    .substring(0, 63);
  if (RESERVED_KEYWORDS.includes(sanitized)) {
    sanitized = `col_${sanitized}`;
  }
  return sanitized;
}

// Database Connection Test
const testDatabaseConnection = async () => {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT NOW(), version()');
    console.log('✅ Database connected:', res.rows[0].version);
    return true;
  } catch (err) {
    console.error('❌ Database connection failed:', err.stack);
    return false;
  } finally {
    client.release();
  }
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
  next();
};

// Email Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() }
});
transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// OTP Generator
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Passport Setup
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, res.rows[0] || false);
  } catch (err) {
    done(err, null);
  }
});

async function findOrCreateUser(profile, provider) {
  const email = profile.emails?.[0]?.value || `${profile.id}@${provider}.com`;
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (rows.length > 0) return rows[0];
  const name = profile.displayName || profile.username || 'No Name';
  const newUser = await pool.query(
    `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [name.trim(), email, true, 'user', provider]
  );
  return newUser.rows[0];
}

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID.trim(),
    clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
    callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await findOrCreateUser(profile, 'google');
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));
}

// Root Route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the ARU-SDMS Backend API',
    status: 'running',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth',
      datasets: '/api/:dataset',
      upload: '/upload/:datasetType'
    }
  });
});

// Dataset Validation
const validateDataset = (req, res, next) => {
  const dataset = req.params.dataset || req.params.datasetType;
  if (!VALID_DATASETS.includes(dataset)) {
    return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
  }
  next();
};

// Dataset Routes
app.get('/api/:dataset', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    console.log(`DEBUG: Querying dataset ${dataset}`);
    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = $1
    `, [dataset]);
    const columns = columnsResult.rows.map(row => row.column_name).filter(col => col !== 'id' && col !== 'geom');

    const result = await pool.query(`
      SELECT id, ST_AsGeoJSON(geom) AS geom, ${columns.map(col => `"${col}"`).join(', ')}
      FROM "${dataset}" ORDER BY id ASC
    `);
    console.log(`DEBUG: Retrieved ${result.rows.length} rows`);

    const features = result.rows.map(row => {
      try {
        const geometry = row.geom ? JSON.parse(row.geom) : null;
        if (!geometry || !geometry.type || !geometry.coordinates) {
          console.warn(`Invalid geometry for id ${row.id}:`, row.geom);
          return null;
        }
        const properties = {};
        for (const key in row) {
          if (key !== 'id' && key !== 'geom') properties[key] = row[key];
        }
        return {
          type: 'Feature',
          id: row.id,
          properties,
          geometry
        };
      } catch (err) {
        console.error(`JSON parse error for id ${row.id}:`, err.stack);
        return null;
      }
    }).filter(feature => feature !== null);

    console.log(`DEBUG: Processed ${features.length} valid features`);
    if (features.length === 0) {
      console.warn(`No valid features found for dataset ${dataset}`);
      return res.status(200).json({ type: 'FeatureCollection', features: [], message: 'No valid GeoJSON features found in dataset' });
    }
    res.json({ type: 'FeatureCollection', features });
  } catch (err) {
    console.error(`DEBUG: Error in /api/${req.params.dataset}:`, err.stack);
    next(err);
  }
});

app.get('/api/:dataset/schema', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    console.log(`DEBUG: Fetching schema for dataset ${dataset}`);
    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = $1
    `, [dataset]);
    const columns = columnsResult.rows
      .map(row => row.column_name)
      .filter(col => col !== 'id' && col !== 'geom');
    res.json({ columns });
  } catch (err) {
    console.error(`DEBUG: Error fetching schema for ${req.params.dataset}:`, err.stack);
    next(err);
  }
});

app.post('/api/:dataset', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    console.log(`DEBUG: Inserting into dataset ${dataset}`);
    const { properties = {}, geometry } = req.body;
    if (!geometry || !geometry.type || !geometry.coordinates) {
      return res.status(400).json({ error: 'Valid GeoJSON geometry required' });
    }

    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = $1
    `, [dataset]);
    const validColumns = columnsResult.rows.map(row => row.column_name).filter(col => col !== 'id' && col !== 'geom');

    const filteredProperties = {};
    for (const key in properties) {
      const sanitizedKey = sanitizeColumnName(key);
      if (validColumns.includes(sanitizedKey) && properties[key] !== null) {
        filteredProperties[sanitizedKey] = String(properties[key]).substring(0, 255);
      }
    }

    const keys = Object.keys(filteredProperties);
    const values = Object.values(filteredProperties);
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
    const columns = keys.map(k => `"${k}"`).join(', ');
    const query = columns
      ? `INSERT INTO "${dataset}" (${columns}, geom) VALUES (${placeholders}, ST_SetSRID(ST_GeomFromGeoJSON($${keys.length + 1}), 4326)) RETURNING *`
      : `INSERT INTO "${dataset}" (geom) VALUES (ST_SetSRID(ST_GeomFromGeoJSON($1), 4326)) RETURNING *`;
    const result = await pool.query(query, [...values, JSON.stringify(geometry)]);
    console.log(`DEBUG: Inserted record with id ${result.rows[0].id}`);
    const { id, geom, ...recordProperties } = result.rows[0];
    res.json({
      message: 'Item uploaded as GeoJSON!',
      record: { id, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
    });
  } catch (err) {
    console.error(`DEBUG: Error inserting into ${req.params.dataset}:`, err.stack);
    next(err);
  }
});

app.put('/api/:dataset/:id', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset, id } = req.params;
    console.log(`DEBUG: Updating dataset ${dataset} id ${id}`);
    const properties = req.body;

    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = $1
    `, [dataset]);
    const validColumns = columnsResult.rows.map(row => row.column_name).filter(col => col !== 'id' && col !== 'geom');

    const filteredProperties = {};
    for (const key in properties) {
      const sanitizedKey = sanitizeColumnName(key);
      if (validColumns.includes(sanitizedKey) && properties[key] !== null) {
        filteredProperties[sanitizedKey] = String(properties[key]).substring(0, 255);
      }
    }

    const keys = Object.keys(filteredProperties);
    const values = Object.values(filteredProperties);
    const setClause = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
    const result = await pool.query(
      `UPDATE "${dataset}" SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
      [...values, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
    console.log(`DEBUG: Updated record id ${id}`);
    const { id: recordId, geom, ...recordProperties } = result.rows[0];
    res.json({
      message: 'Updated!',
      record: { id: recordId, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
    });
  } catch (err) {
    console.error(`DEBUG: Error updating ${req.params.dataset}/${id}:`, err.stack);
    next(err);
  }
});

app.delete('/api/:dataset/:id', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset, id } = req.params;
    console.log(`DEBUG: Deleting from dataset ${dataset} id ${id}`);
    const result = await pool.query(`DELETE FROM "${dataset}" WHERE id = $1 RETURNING id`, [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
    console.log(`DEBUG: Deleted record id ${id}`);
    res.json({ message: 'Deleted!' });
  } catch (err) {
    console.error(`DEBUG: Error deleting from ${req.params.dataset}/${id}:`, err.stack);
    next(err);
  }
});

// Auth Routes
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    const emailLower = email.toLowerCase().trim();
    const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
    if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, 12);
    const otp = generateOTP();
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
      [name.trim(), emailLower, hashedPassword, false, otp, 'user']
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: emailLower,
      subject: 'Verify your account',
      text: `Your OTP is: ${otp}`,
      html: `<p>Your OTP is: <strong>${otp}</strong></p>`
    });
    res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
  } catch (err) {
    console.error('Error in register:', err.stack);
    next(err);
  }
});

app.post('/api/auth/verify-otp', async (req, res, next) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
    const emailLower = email.toLowerCase().trim();
    const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];
    if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
    if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
    res.json({ message: 'Email verified' });
  } catch (err) {
    console.error('Error in verify-otp:', err.stack);
    next(err);
  }
});

app.post('/api/auth/resend-otp', async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const emailLower = email.toLowerCase().trim();
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const otp = generateOTP();
    await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: emailLower,
      subject: 'Resend Verification OTP',
      text: `Your new OTP is: ${otp}`,
      html: `<p>Your new OTP is: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'New OTP sent to your email' });
  } catch (err) {
    console.error('Error in resend-otp:', err.stack);
    next(err);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const emailLower = email.toLowerCase().trim();
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
    res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Error in login:', err.stack);
    next(err);
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: err.message });
    req.session.destroy(err => {
      if (err) return res.status(500).json({ error: err.message });
      res.clearCookie('connect.sid');
      res.json({ message: 'Logged out' });
    });
  });
});

app.post('/api/auth/reset-password-request', async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const emailLower = email.toLowerCase().trim();
    const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const otp = generateOTP();
    await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: emailLower,
      subject: 'Reset Password OTP',
      text: `Your OTP is: ${otp}`,
      html: `<p>Your OTP is: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'Reset password OTP sent' });
  } catch (err) {
    console.error('Error in reset-password-request:', err.stack);
    next(err);
  }
});

app.post('/api/auth/reset-password', async (req, res, next) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });
    const emailLower = email.toLowerCase().trim();
    const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];
    if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Error in reset-password:', err.stack);
    next(err);
  }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: `${process.env.CLIENT_URL}/login?error=auth_failed`
}), (req, res) => {
  try {
    const token = jwt.sign(
      { id: req.user.id, email: req.user.email, role: req.user.role },
      process.env.JWT_SECRET.trim(),
      { expiresIn: '7d' }
    );
    console.log(`DEBUG: Google auth callback successful, redirecting with token for user ${req.user.email}`);
    res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
  } catch (err) {
    console.error('DEBUG: Error in Google auth callback:', err.stack);
    res.redirect(`${process.env.CLIENT_URL}/login?error=auth_failed`);
  }
});

// Health Check
app.get('/api/health', async (req, res) => {
  const dbStatus = await testDatabaseConnection();
  res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
});

// Import GeoJSON upload route
app.use('/upload', geojsonUpload);

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(`❌ Server Error [${req.method} ${req.originalUrl}]:`, err.stack);
  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal Server Error',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
});

// 404 Fallback
app.use((req, res) => {
  console.log(`DEBUG: 404 Route not found for ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: 'Route not found' });
});

// Start Server
async function startServer() {
  try {
    await testDatabaseConnection();
    await initializeTables();
    await redisClient.connect();
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`DEBUG: Route /upload/buildings registered`);
    });
    server.on('error', (err) => {
      console.error('❌ Server startup error:', err.message);
      process.exit(1);
    });
  } catch (err) {
    console.error('❌ Startup error:', err.stack);
    process.exit(1);
  }
}

startServer();