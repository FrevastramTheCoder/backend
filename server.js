

// // =============================================
// // MODULE IMPORTS
// // =============================================
// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session'); // Added for session support
// const { Pool } = require('pg');
// const multer = require('multer');
// const fs = require('fs');
// const shapefile = require('shapefile');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const { promisify } = require('util');``
// const AdmZip = require('adm-zip');

// const passport = require('passport');
// const FacebookStrategy = require('passport-facebook').Strategy;
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const TwitterStrategy = require('passport-twitter').Strategy;

// const nodemailer = require('nodemailer');

// const unlinkAsync = promisify(fs.unlink);
// const rmdirAsync = promisify(fs.rm || fs.rmdir);

// // =============================================
// // APP INITIALIZATION
// // =============================================
// const app = express();
// const PORT = process.env.PORT || 5000;

// // =============================================
// // CONFIG VALIDATION (Updated with SESSION_SECRET)
// // =============================================
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CLIENT_URL', 'SERVER_URL',
//     'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET',
//     'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
//     'TWITTER_CONSUMER_KEY', 'TWITTER_CONSUMER_SECRET',
//   ];
//   const missingVars = requiredVars.filter(v => !process.env[v]);

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:');
//     console.table(missingVars.map(varName => ({
//       Variable: varName,
//       Status: 'MISSING',
//       'Expected Location': path.resolve(__dirname, '.env')
//     })));
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
//   console.table(requiredVars.map(varName => ({
//     Variable: varName,
//     Status: 'PRESENT',
//     Value: varName.toLowerCase().includes('secret') ? '*****' : process.env[varName]
//   })));
// };

// validateConfig();

// // =============================================
// // MIDDLEWARE (Updated with session configuration)
// // =============================================
// app.use(cors({
//   origin: process.env.CORS_ORIGIN?.split(',') || '*',
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
//   credentials: true // Required for sessions
// }));

// // Session middleware - MUST come before passport
// app.use(session({
//   secret: process.env.SESSION_SECRET,
//   resave: false,
//   saveUninitialized: false,
//   cookie: {
//     secure: process.env.NODE_ENV === 'production', // Enable in production (HTTPS)
//     maxAge: 24 * 60 * 60 * 1000, // 24 hours
//     sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
//   }
// }));

// app.use(express.json({
//   limit: '50mb',
//   verify: (req, res, buf) => {
//     req.rawBody = buf.toString();
//   }
// }));

// app.use(express.urlencoded({
//   extended: true,
//   limit: '50mb',
//   parameterLimit: 1000
// }));

// // Initialize passport AFTER session middleware
// app.use(passport.initialize());
// app.use(passport.session()); // Required for persistent login sessions

// // =============================================
// // ROOT ROUTE
// // =============================================
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: {
//       health: '/api/health',
//       auth: {
//         register: '/api/auth/register',
//         login: '/api/auth/login',
//         google: '/auth/google',
//         facebook: '/auth/facebook',
//         twitter: '/auth/twitter'
//       },
//       datasets: '/api/:dataset (requires authentication)'
//     }
//   });
// });

// // =============================================
// // DATABASE CONNECTION
// // =============================================
// const pool = new Pool({
//   user: process.env.DB_USER,
//   host: process.env.DB_HOST,
//   database: process.env.DB_NAME,
//   password: process.env.DB_PASS,
//   port: Number(process.env.DB_PORT),
//   ssl: process.env.DB_SSL === 'true' ? {
//     rejectUnauthorized: false,
//     ca: process.env.DB_CA_CERT
//   } : false,
//   connectionTimeoutMillis: 10000,
//   idleTimeoutMillis: 30000,
//   max: 20,
//   allowExitOnIdle: true
// });

// const testDatabaseConnection = async () => {
//   const start = Date.now();
//   let client;
//   try {
//     client = await pool.connect();
//     const res = await client.query('SELECT NOW(), version()');
//     const duration = Date.now() - start;
//     console.log('✅ Database connection established:');
//     console.table([{
//       'Connection Time': `${duration}ms`,
//       'PostgreSQL Version': res.rows[0].version.split(' ')[1],
//       'Current Timestamp': res.rows[0].now
//     }]);
//   } catch (err) {
//     console.error('❌ Database connection failed:', err);
//     process.exit(1);
//   } finally {
//     if (client) client.release();
//   }
// };

// // =============================================
// // AUTH MIDDLEWARE
// // =============================================
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', message: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // =============================================
// // EMAIL TRANSPORTER (Nodemailer)
// // =============================================
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS,
//   },
// });

// // =============================================
// // OTP GENERATOR HELPER
// // =============================================
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // =============================================
// // PASSPORT SOCIAL STRATEGIES SETUP
// // =============================================
// passport.serializeUser((user, done) => done(null, user.id));

// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     if (res.rows.length === 0) return done(null, false);
//     done(null, res.rows[0]);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('Email not found in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const { rows: [newUser] } = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) 
//      VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   );
//   return newUser;
// }

// passport.use(new FacebookStrategy({
//   clientID: process.env.FACEBOOK_CLIENT_ID,
//   clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
//   callbackURL: `${process.env.SERVER_URL}/auth/facebook/callback`,
//   profileFields: ['id', 'displayName', 'emails']
// }, async (accessToken, refreshToken, profile, done) => {
//   try {
//     const user = await findOrCreateUser(profile, 'facebook');
//     done(null, user);
//   } catch (err) {
//     done(err, null);
//   }
// }));

// passport.use(new GoogleStrategy({
//   clientID: process.env.GOOGLE_CLIENT_ID,
//   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//   callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
// }, async (accessToken, refreshToken, profile, done) => {
//   try {
//     const user = await findOrCreateUser(profile, 'google');
//     done(null, user);
//   } catch (err) {
//     done(err, null);
//   }
// }));

// passport.use(new TwitterStrategy({
//   consumerKey: process.env.TWITTER_CONSUMER_KEY,
//   consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
//   callbackURL: `${process.env.SERVER_URL}/auth/twitter/callback`,
//   includeEmail: true
// }, async (token, tokenSecret, profile, done) => {
//   try {
//     const user = await findOrCreateUser(profile, 'twitter');
//     done(null, user);
//   } catch (err) {
//     done(err, null);
//   }
// }));

// // =============================================
// // DATASET ROUTES
// // =============================================
// const VALID_DATASETS = [
//   "buildings", "footpaths", "electricitySupply", "securityLights", "roads",
//   "drainage-systems", "recreationalAreas", "vimbweta", "solidWasteCollection",
//   "parking", "vegetation"
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) {
//     return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   }
//   next();
// };

// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT id, properties FROM ${dataset} ORDER BY id ASC`);
//     res.json({ features: result.rows });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const result = await pool.query(
//       `INSERT INTO ${dataset} (properties) VALUES ($1) RETURNING id, properties`,
//       [properties]
//     );
//     res.status(201).json({ message: 'Item uploaded!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const result = await pool.query(
//       `UPDATE ${dataset} SET properties = $1 WHERE id = $2 RETURNING id, properties`,
//       [properties, id]
//     );
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Updated!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM ${dataset} WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // =============================================
// // MULTER CONFIGURATION FOR SHAPEFILE UPLOAD
// // =============================================
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = path.resolve(__dirname, 'uploads/shapefiles');
//     if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
//     cb(null, uniqueSuffix + '-' + file.originalname);
//   }
// });

// const fileFilter = (req, file, cb) => {
//   if (file.mimetype === 'application/zip' || file.originalname.match(/\.zip$/i)) {
//     cb(null, true);
//   } else {
//     const err = new Error('Only .zip files are allowed!');
//     err.code = 'LIMIT_FILE_TYPES';
//     cb(err, false);
//   }
// };

// const upload = multer({
//   storage,
//   limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
//   fileFilter
// }).single('file');

// // =============================================
// // SHAPEFILE UPLOAD ROUTE
// // =============================================
// app.post('/upload/:dataset', authenticate, validateDataset, (req, res, next) => {
//   upload(req, res, async (err) => {
//     if (err) {
//       if (err.code === 'LIMIT_FILE_TYPES') {
//         return res.status(422).json({ error: 'Only .zip files allowed!' });
//       }
//       if (err.code === 'LIMIT_FILE_SIZE') {
//         return res.status(422).json({ error: 'File too large. Max 50MB allowed!' });
//       }
//       return res.status(400).json({ error: err.message });
//     }

//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     const zipPath = req.file.path;
//     const extractDir = path.resolve('temp', `shp_${Date.now()}_${Math.random().toString(36).slice(2)}`);

//     try {
//       fs.mkdirSync(extractDir, { recursive: true });
//       const zip = new AdmZip(zipPath);
//       zip.extractAllTo(extractDir, true);

//       // Find required shapefile components
//       const files = fs.readdirSync(extractDir);
//       const shpFile = files.find(f => f.toLowerCase().endsWith('.shp'));
//       const dbfFile = files.find(f => f.toLowerCase().endsWith('.dbf'));
//       if (!shpFile || !dbfFile) {
//         throw new Error('Shapefile (.shp) or DBF (.dbf) files missing in ZIP');
//       }

//       const shpFilePath = path.join(extractDir, shpFile);
//       const dbfFilePath = path.join(extractDir, dbfFile);

//       // Open shapefile and read features
//       const source = await shapefile.open(shpFilePath, dbfFilePath);

//       let resultFeature = await source.read();
//       if (resultFeature.done) {
//         throw new Error('Shapefile contains no features');
//       }

//       const client = await pool.connect();
//       try {
//         await client.query('BEGIN');

//         await client.query(`
//           CREATE TABLE IF NOT EXISTS ${req.params.dataset} (
//             id SERIAL PRIMARY KEY,
//             properties JSONB
//           )
//         `);

//         while (!resultFeature.done) {
//           const feature = resultFeature.value;
//           await client.query(
//             `INSERT INTO ${req.params.dataset} (properties) VALUES ($1)`,
//             [feature.properties || feature]
//           );
//           resultFeature = await source.read();
//         }

//         await client.query('COMMIT');
//       } catch (dbErr) {
//         await client.query('ROLLBACK');
//         throw dbErr;
//       } finally {
//         client.release();
//       }

//       await unlinkAsync(zipPath);
//       await rmdirAsync(extractDir, { recursive: true, force: true });

//       res.json({ message: 'Shapefile uploaded and processed successfully!' });
//     } catch (error) {
//       try { await unlinkAsync(zipPath); } catch {}
//       try { await rmdirAsync(extractDir, { recursive: true, force: true }); } catch {}
//       next(error);
//     }
//   });
// });

// // =============================================
// // AUTH ROUTES
// // =============================================

// // Registration with OTP email verification
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password, role = 'user' } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'Missing required fields' });

//     const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
//     if (userExists.rows.length > 0) return res.status(409).json({ error: 'Email already in use' });

//     const hashedPassword = await bcrypt.hash(password, 10);
//     const otp = generateOTP();
//     const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

//     const newUser = await pool.query(
//       `INSERT INTO users (name, email, password, role, is_verified, otp, otp_expires) 
//        VALUES ($1, $2, $3, $4, $5, $6, $7)
//        RETURNING id, name, email, role`,
//       [name, email, hashedPassword, role, false, otp, otpExpires]
//     );

//     // Send OTP email
//     await transporter.sendMail({
//       from: `"Your App" <${process.env.EMAIL_USER}>`,
//       to: email,
//       subject: 'Verify your email OTP',
//       text: `Your OTP code is: ${otp}. It expires in 10 minutes.`,
//       html: `<p>Your OTP code is: <strong>${otp}</strong>. It expires in 10 minutes.</p>`
//     });

//     res.status(201).json({
//       success: true,
//       message: 'Registration successful, please verify your email using OTP',
//       user: {
//         id: newUser.rows[0].id,
//         name,
//         email,
//         role
//       }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// // OTP verification route
// app.post('/api/auth/verify-otp', async (req, res) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ message: 'Email and OTP are required' });

//     const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });

//     const user = userRes.rows[0];
//     if (user.is_verified) return res.status(400).json({ message: 'User already verified' });

//     if (user.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

//     if (new Date(user.otp_expires) < new Date()) return res.status(400).json({ message: 'OTP expired' });

//     await pool.query('UPDATE users SET is_verified = TRUE, otp = NULL, otp_expires = NULL WHERE email = $1', [email]);

//     res.json({ message: 'Email verified successfully!' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Login route
// app.post('/api/auth/login', async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

//     const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });

//     const user = userRes.rows[0];
//     if (!user.is_verified) return res.status(401).json({ message: 'Email not verified' });

//     const validPass = await bcrypt.compare(password, user.password);
//     if (!validPass) return res.status(401).json({ message: 'Incorrect password' });

//     const token = jwt.sign(
//       { id: user.id, email: user.email, role: user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: '1d' }
//     );

//     res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Password reset request route
// app.post('/api/auth/reset-password-request', async (req, res) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ message: 'Email required' });

//     const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });

//     const otp = generateOTP();
//     const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

//     await pool.query('UPDATE users SET otp = $1, otp_expires = $2 WHERE email = $3', [otp, otpExpires, email]);

//     await transporter.sendMail({
//       from: `"Your App" <${process.env.EMAIL_USER}>`,
//       to: email,
//       subject: 'Password Reset OTP',
//       text: `Your password reset OTP is: ${otp}. It expires in 10 minutes.`,
//       html: `<p>Your password reset OTP is: <strong>${otp}</strong>. It expires in 10 minutes.</p>`
//     });

//     res.json({ message: 'Password reset OTP sent to email' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Password reset verification & update
// app.post('/api/auth/reset-password', async (req, res) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ message: 'Email, OTP and new password required' });

//     const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });

//     const user = userRes.rows[0];
//     if (user.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
//     if (new Date(user.otp_expires) < new Date()) return res.status(400).json({ message: 'OTP expired' });

//     const hashedPassword = await bcrypt.hash(newPassword, 10);
//     await pool.query('UPDATE users SET password = $1, otp = NULL, otp_expires = NULL WHERE email = $2', [hashedPassword, email]);

//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // =============================================
// // SOCIAL AUTH ROUTES
// // =============================================

// app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

// app.get('/auth/facebook/callback',
//   passport.authenticate('facebook', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//   (req, res) => {
//     // On success, issue JWT token and redirect or respond with token
//     const token = jwt.sign(
//       { id: req.user.id, email: req.user.email, role: req.user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: '1d' }
//     );
//     res.redirect(`${process.env.CLIENT_URL}/social-login?token=${token}`);
//   }
// );

// app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// app.get('/auth/google/callback',
//   passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//   (req, res) => {
//     const token = jwt.sign(
//       { id: req.user.id, email: req.user.email, role: req.user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: '1d' }
//     );
//     res.redirect(`${process.env.CLIENT_URL}/social-login?token=${token}`);
//   }
// );

// app.get('/auth/twitter', passport.authenticate('twitter'));

// app.get('/auth/twitter/callback',
//   passport.authenticate('twitter', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//   (req, res) => {
//     const token = jwt.sign(
//       { id: req.user.id, email: req.user.email, role: req.user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: '1d' }
//     );
//     res.redirect(`${process.env.CLIENT_URL}/social-login?token=${token}`);
//   }
// );

// // =============================================
// // HEALTH CHECK ROUTE
// // =============================================
// app.get('/api/health', async (req, res) => {
//   try {
//     const client = await pool.connect();
//     await client.query('SELECT 1');
//     client.release();
//     res.json({ status: 'ok', db: 'connected' });
//   } catch (err) {
//     res.status(500).json({ status: 'error', error: err.message });
//   }
// });

// // =============================================
// // GLOBAL ERROR HANDLER
// // =============================================
// app.use((err, req, res, next) => {
//   console.error(err.stack);
//   if (res.headersSent) return next(err);
//   res.status(500).json({ error: err.message || 'Internal Server Error' });
// });

// // =============================================
// // START SERVER AFTER DB TEST
// // =============================================
// testDatabaseConnection().then(() => {
//   app.listen(PORT, () => {
//     console.log(`🚀 Server started on port ${PORT}`);
//   });
// });

// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const multer = require('multer');
// const fs = require('fs');
// const shapefile = require('shapefile');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const { promisify } = require('util');
// const AdmZip = require('adm-zip');
// const passport = require('passport');
// const FacebookStrategy = require('passport-facebook').Strategy;
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const TwitterStrategy = require('passport-twitter').Strategy;
// const nodemailer = require('nodemailer');

// const unlinkAsync = promisify(fs.unlink);
// const rmdirAsync = promisify(fs.rm || fs.rmdir);

// // =============================================
// // APP INITIALIZATION
// // =============================================
// const app = express();
// const PORT = process.env.PORT || 10000;

// // =============================================
// // CONFIG VALIDATION
// // =============================================
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = [
//     'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET',
//     'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
//     'TWITTER_CONSUMER_KEY', 'TWITTER_CONSUMER_SECRET'
//   ];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:');
//     console.table(missingVars.map(varName => ({
//       Variable: varName,
//       Status: 'MISSING',
//       'Expected Location': path.resolve(__dirname, '.env')
//     })));
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
//   console.table([...requiredVars, ...optionalVars].map(varName => ({
//     Variable: varName,
//     Status: process.env[varName] ? 'PRESENT' : 'NOT PRESENT',
//     Value: varName.toLowerCase().includes('secret') || varName.toLowerCase().includes('pass')
//       ? '*****'
//       : process.env[varName] || 'N/A'
//   })));

//   optionalVars.forEach(varName => {
//     if (process.env[varName] && process.env[varName].startsWith('your_')) {
//       console.warn(`⚠️ Warning: ${varName} appears to be a placeholder value: ${process.env[varName]}`);
//     }
//   });
// };
// validateConfig();

// // =============================================
// // REDIS CLIENT SETUP WITH FALLBACK MEMORY STORE
// // =============================================
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => {
//       if (retries > 10) {
//         if (!redisErrorLogged) {
//           console.warn('⚠️ Redis connection failed after 10 retries, falling back to in-memory session store');
//           redisErrorLogged = true;
//           sessionStore = new session.MemoryStore();
//         }
//         return false; // stop retrying
//       }
//       return Math.min(retries * 100, 3000); // retry delay
//     }
//   }
// });

// redisClient.on('error', err => {
//   if (redisErrorLogged) return;
//   if (err.code === 'ENOTFOUND') {
//     console.error(`Redis DNS Error: Cannot resolve ${process.env.REDIS_URL}. Check REDIS_URL.`);
//   } else {
//     console.error('Redis Client Error:', err);
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });
// redisClient.on('end', () => {
//   if (!redisErrorLogged) {
//     console.log('Redis Client Disconnected');
//     redisErrorLogged = true;
//   }
// });

// // Start Redis connection and fallback if it fails
// sessionStore = new session.MemoryStore();
// redisClient.connect().catch(err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Connection Failed:', err);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });

// // =============================================
// // MIDDLEWARE
// // =============================================
// app.use(cors({
//   origin: process.env.CORS_ORIGIN.trim(),
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: {
//     secure: process.env.NODE_ENV === 'production',
//     maxAge: 24 * 60 * 60 * 1000,
//     sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
//   }
// }));

// app.use(express.json({
//   limit: '50mb',
//   verify: (req, res, buf) => { req.rawBody = buf.toString(); }
// }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));

// app.use(passport.initialize());
// app.use(passport.session());

// // =============================================
// // ROOT ROUTE
// // =============================================
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: {
//       health: '/api/health',
//       auth: {
//         register: '/api/auth/register',
//         login: '/api/auth/login',
//         google: '/auth/google',
//         facebook: '/auth/facebook',
//         twitter: '/auth/twitter'
//       },
//       datasets: '/api/:dataset (requires authentication)'
//     }
//   });
// });

// // =============================================
// // DATABASE CONNECTION
// // =============================================
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false },
//   connectionTimeoutMillis: 10000,
//   idleTimeoutMillis: 30000,
//   max: 20,
//   allowExitOnIdle: true
// });

// pool.on('error', (err) => console.error('PostgreSQL Pool Error:', err));

// const testDatabaseConnection = async () => {
//   const start = Date.now();
//   let client;
//   try {
//     client = await pool.connect();
//     const res = await client.query('SELECT NOW(), version()');
//     const duration = Date.now() - start;
//     console.log('✅ Database connection established:');
//     console.table([{
//       'Connection Time': `${duration}ms`,
//       'PostgreSQL Version': res.rows[0].version.split(' ')[1],
//       'Current Timestamp': res.rows[0].now
//     }]);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err);
//     return false;
//   } finally {
//     if (client) client.release();
//   }
// };

// // =============================================
// // AUTH MIDDLEWARE
// // =============================================
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', message: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // =============================================
// // EMAIL TRANSPORTER (Nodemailer)
// // =============================================
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: {
//     user: process.env.EMAIL_USER.trim(),
//     pass: process.env.EMAIL_PASS.trim(),
//   },
// });

// transporter.verify((error, success) => {
//   if (error) console.error('❌ Email Transporter Error:', error);
//   else console.log('✅ Email Transporter Ready');
// });

// // =============================================
// // OTP GENERATOR HELPER
// // =============================================
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // =============================================
// // PASSPORT SOCIAL STRATEGIES SETUP
// // =============================================
// passport.serializeUser((user, done) => done(null, user.id));

// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     if (res.rows.length === 0) return done(null, false);
//     done(null, res.rows[0]);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('Email not found in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const { rows: [newUser] } = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) 
//      VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   );
//   return newUser;
// }

// if (process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET && 
//     !process.env.FACEBOOK_CLIENT_ID.startsWith('your_')) {
//   passport.use(new FacebookStrategy({
//     clientID: process.env.FACEBOOK_CLIENT_ID.trim(),
//     clientSecret: process.env.FACEBOOK_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/facebook/callback`,
//     profileFields: ['id', 'displayName', 'emails']
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'facebook');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// } else {
//   console.warn('⚠️ Facebook authentication disabled: Invalid or missing credentials');
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && 
//     !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// } else {
//   console.warn('⚠️ Google authentication disabled: Invalid or missing credentials');
// }

// if (process.env.TWITTER_CONSUMER_KEY && process.env.TWITTER_CONSUMER_SECRET && 
//     !process.env.TWITTER_CONSUMER_KEY.startsWith('your_')) {
//   passport.use(new TwitterStrategy({
//     consumerKey: process.env.TWITTER_CONSUMER_KEY.trim(),
//     consumerSecret: process.env.TWITTER_CONSUMER_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/twitter/callback`,
//     includeEmail: true
//   }, async (token, tokenSecret, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'twitter');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// } else {
//   console.warn('⚠️ Twitter authentication disabled: Invalid or missing credentials');
// }

// // =============================================
// // DATASET ROUTES
// // =============================================
// const VALID_DATASETS = [
//   "buildings", "footpaths", "electricitySupply", "securityLights", "roads",
//   "drainage-systems", "recreationalAreas", "vimbweta", "solidWasteCollection",
//   "parking", "vegetation"
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) {
//     return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   }
//   next();
// };

// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT id, properties FROM ${dataset} ORDER BY id ASC`);
//     res.json({ features: result.rows });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const result = await pool.query(
//       `INSERT INTO ${dataset} (properties) VALUES ($1) RETURNING id, properties`,
//       [properties]
//     );
//     res.status(201).json({ message: 'Item uploaded!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const result = await pool.query(
//       `UPDATE ${dataset} SET properties = $1 WHERE id = $2 RETURNING id, properties`,
//       [properties, id]
//     );
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Updated!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM ${dataset} WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // =============================================
// // MULTER CONFIGURATION FOR SHAPEFILE UPLOAD
// // =============================================
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = path.resolve(__dirname, 'Uploads/shapefiles');
//     if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
//     cb(null, uniqueSuffix + '-' + file.originalname);
//   }
// });

// const fileFilter = (req, file, cb) => {
//   if (file.mimetype === 'application/zip' || file.originalname.match(/\.zip$/i)) {
//     cb(null, true);
//   } else {
//     const err = new Error('Only .zip files are allowed!');
//     err.code = 'LIMIT_FILE_TYPES';
//     cb(err, false);
//   }
// };

// const upload = multer({
//   storage,
//   fileFilter,
//   limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
// }).single('shapefile');

// // =============================================
// // SHAPEFILE UPLOAD ROUTE
// // =============================================
// app.post('/api/shapefile/upload', authenticate, (req, res) => {
//   upload(req, res, async function (err) {
//     if (err) {
//       if (err.code === 'LIMIT_FILE_TYPES') {
//         return res.status(422).json({ error: err.message });
//       }
//       if (err.code === 'LIMIT_FILE_SIZE') {
//         return res.status(422).json({ error: 'File too large. Max 10MB allowed.' });
//       }
//       return res.status(500).json({ error: err.message });
//     }
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     const zipPath = req.file.path;
//     const unzipDir = path.join(path.dirname(zipPath), path.basename(zipPath, '.zip'));

//     try {
//       const zip = new AdmZip(zipPath);
//       zip.extractAllTo(unzipDir, true);

//       // Find .shp file inside extracted folder
//       const files = fs.readdirSync(unzipDir);
//       const shpFile = files.find(f => f.toLowerCase().endsWith('.shp'));
//       if (!shpFile) throw new Error('No .shp file found in the ZIP');

//       // Read shapefile
//       const shpFilePath = path.join(unzipDir, shpFile);
//       const geojson = { type: 'FeatureCollection', features: [] };

//       const source = await shapefile.open(shpFilePath);
//       while (true) {
//         const result = await source.read();
//         if (result.done) break;
//         geojson.features.push({ type: 'Feature', geometry: result.value.geometry, properties: result.value.properties });
//       }

//       // Cleanup files after reading
//       await unlinkAsync(zipPath);
//       await rmdirAsync(unzipDir, { recursive: true, force: true });

//       res.json({ message: 'Shapefile uploaded and processed', data: geojson });
//     } catch (error) {
//       // Cleanup files on error too
//       try {
//         await unlinkAsync(zipPath);
//         await rmdirAsync(unzipDir, { recursive: true, force: true });
//       } catch (cleanupErr) {
//         console.error('Error cleaning up after shapefile error:', cleanupErr);
//       }
//       res.status(500).json({ error: error.message });
//     }
//   });
// });

// // =============================================
// // AUTH ROUTES
// // =============================================

// // Register
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password required' });

//     const emailLower = email.toLowerCase();
//     const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
//     if (userExists.rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) 
//        VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name, emailLower, hashedPassword, false, otp, 'user']
//     );

//     // Send OTP email
//     await transporter.sendMail({
//       from: `"ARU-SDMS" <${process.env.EMAIL_USER.trim()}>`,
//       to: emailLower,
//       subject: 'Verify your account OTP',
//       text: `Your OTP code is: ${otp}. It will expire shortly.`,
//       html: `<p>Your OTP code is: <b>${otp}</b>. It will expire shortly.</p>`
//     });

//     res.status(201).json({ message: 'User registered. Please verify your email.', user: { id: rows[0].id, name: rows[0].name, email: rows[0].email } });
//   } catch (err) {
//     next(err);
//   }
// });

// // Verify OTP
// app.post('/api/auth/verify', async (req, res, next) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'User already verified' });

//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);

//     res.json({ message: 'Email verified successfully. You can now login.' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Login
// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const passwordMatch = await bcrypt.compare(password, user.password);
//     if (!passwordMatch) return res.status(401).json({ error: 'Invalid email or password' });

//     const tokenPayload = { id: user.id, email: user.email, role: user.role };
//     const token = jwt.sign(tokenPayload, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });

//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// // Logout (optional, if using sessions)
// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: 'Logout failed' });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out successfully' });
//     });
//   });
// });

// // =============================================
// // SOCIAL AUTH ROUTES
// // =============================================
// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
//   app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

//   app.get('/auth/google/callback',
//     passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       // Generate JWT after successful login
//       const tokenPayload = { id: req.user.id, email: req.user.email, role: req.user.role };
//       const token = jwt.sign(tokenPayload, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${token}`);
//     }
//   );
// }

// if (process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET) {
//   app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

//   app.get('/auth/facebook/callback',
//     passport.authenticate('facebook', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       const tokenPayload = { id: req.user.id, email: req.user.email, role: req.user.role };
//       const token = jwt.sign(tokenPayload, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${token}`);
//     }
//   );
// }

// if (process.env.TWITTER_CONSUMER_KEY && process.env.TWITTER_CONSUMER_SECRET) {
//   app.get('/auth/twitter', passport.authenticate('twitter'));

//   app.get('/auth/twitter/callback',
//     passport.authenticate('twitter', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       const tokenPayload = { id: req.user.id, email: req.user.email, role: req.user.role };
//       const token = jwt.sign(tokenPayload, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${token}`);
//     }
//   );
// }

// // =============================================
// // HEALTH CHECK ROUTE
// // =============================================
// app.get('/api/health', async (req, res) => {
//   const dbConnected = await testDatabaseConnection();
//   const redisConnected = redisClient.isReady;

//   res.json({
//     status: 'ok',
//     database: dbConnected ? 'connected' : 'disconnected',
//     redis: redisConnected ? 'connected' : 'disconnected',
//     serverTime: new Date()
//   });
// });

// // =============================================
// // GLOBAL ERROR HANDLER
// // =============================================
// app.use((err, req, res, next) => {
//   console.error('Server Error:', err);
//   const status = err.status || 500;
//   res.status(status).json({ error: err.message || 'Internal Server Error' });
// });

// // =============================================
// // START SERVER
// // =============================================
// (async () => {
//   await testDatabaseConnection();

//   if (!redisClient.isReady) {
//     console.warn('⚠️ Redis not connected. Using in-memory session store. Sessions will not persist.');
//   }

//   app.listen(PORT, () => {
//     console.log(`🚀 Server running on port ${PORT}`);
//   });
// })();

// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const multer = require('multer');
// const fs = require('fs');
// const shapefile = require('shapefile');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const { promisify } = require('util');
// const AdmZip = require('adm-zip');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');

// const unlinkAsync = promisify(fs.unlink);
// const rmdirAsync = promisify(fs.rm || fs.rmdir);

// const app = express();
// const PORT = process.env.PORT || 10000;

// // Configuration Validation
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:', missingVars);
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
// };
// validateConfig();

// // Rate Limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100 // Limit each IP to 100 requests per windowMs
// });
// app.use(limiter);

// // Redis Client Setup
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
//   }
// });

// redisClient.on('error', err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Client Error:', err.message);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });

// (async () => {
//   try {
//     await redisClient.connect();
//   } catch (err) {
//     console.error('Redis Connection Failed:', err.message);
//     sessionStore = new session.MemoryStore();
//   }
// })();

// // Middleware
// app.use(cors({
//   origin: (origin, callback) => {
//     const allowedOrigins = [
//       'https://aru-sdms.vercel.app',
//       'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app'
//     ];
//     if (!origin || allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
// }));

// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
// app.use(passport.initialize());
// app.use(passport.session());

// // Root Route
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset' }
//   });
// });

// // Database Connection
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false }
// });

// pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

// const testDatabaseConnection = async () => {
//   const client = await pool.connect();
//   try {
//     const res = await client.query('SELECT NOW(), version()');
//     console.log('✅ Database connected:', res.rows[0].version);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//     return false;
//   } finally {
//     client.release();
//   }
// };

// // Auth Middleware
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', details: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // Email Transporter
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
// });
// transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// // OTP Generator
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // Passport Setup
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     done(null, res.rows[0] || false);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('No email in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const [newUser] = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   ).rows;
//   return newUser;
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation'
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   next();
// };

// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT id, properties FROM ${dataset} ORDER BY id ASC`);
//     res.json({ features: result.rows });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const result = await pool.query(`INSERT INTO ${dataset} (properties) VALUES ($1) RETURNING id, properties`, [properties]);
//     res.status(201).json({ message: 'Item uploaded!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const result = await pool.query(`UPDATE ${dataset} SET properties = $1 WHERE id = $2 RETURNING id, properties`, [properties, id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Updated!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM ${dataset} WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = path.join(__dirname, 'Uploads', 'shapefiles');
//     if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
//     cb(null, `${uniqueSuffix}-${file.originalname}`);
//   }
// });

// const fileFilter = (req, file, cb) => {
//   if (file.mimetype === 'application/zip' || file.originalname.match(/\.(zip)$/i)) {
//     cb(null, true);
//   } else {
//     cb(new Error('Only .zip files are allowed!'), false);
//   }
// };

// const upload = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } }).single('shapefile');

// app.post('/api/shapefile/upload', authenticate, (req, res) => {
//   upload(req, res, async (err) => {
//     if (err) {
//       return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.message });
//     }
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     const zipPath = req.file.path;
//     const unzipDir = path.join(path.dirname(zipPath), path.basename(zipPath, '.zip'));

//     try {
//       const zip = new AdmZip(zipPath);
//       zip.extractAllTo(unzipDir, true);

//       const files = fs.readdirSync(unzipDir);
//       const shpFile = files.find(f => f.toLowerCase().endsWith('.shp'));
//       if (!shpFile) throw new Error('No .shp file found in the ZIP');

//       const shpFilePath = path.join(unzipDir, shpFile);
//       const geojson = { type: 'FeatureCollection', features: [] };

//       const source = await shapefile.open(shpFilePath);
//       for await (const result of source) {
//         geojson.features.push({ type: 'Feature', geometry: result.geometry, properties: result.properties });
//       }

//       await unlinkAsync(zipPath);
//       await rmdirAsync(unzipDir, { recursive: true, force: true });

//       res.json({ message: 'Shapefile uploaded and processed', data: geojson });
//     } catch (error) {
//       await unlinkAsync(zipPath).catch(() => {});
//       await rmdirAsync(unzipDir, { recursive: true, force: true }).catch(() => {});
//       res.status(500).json({ error: error.message });
//     }
//   });
// });

// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
//     if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name.trim(), emailLower, hashedPassword, false, otp, 'user']
//     );

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Verify your account',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/verify', async (req, res, next) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
//     res.json({ message: 'Email verified' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out' });
//     });
//   });
// });

// app.post('/api/auth/reset-password-request', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Reset Password OTP',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'Reset password OTP sent' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/reset-password', async (req, res, next) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     const hashedPassword = await bcrypt.hash(newPassword, 12);
//     await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     next(err);
//   }
// });

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

//   app.get('/auth/google/callback',
//     passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
//     }
//   );
// }

// app.get('/api/health', async (req, res) => {
//   const dbStatus = await testDatabaseConnection();
//   res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
// });

// app.use((err, req, res, next) => {
//   console.error('Server Error:', err.stack);
//   res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
// });

// (async () => {
//   await testDatabaseConnection();
//   app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
// })();

// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const multer = require('multer');
// const fs = require('fs');
// const shapefile = require('shapefile');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const { promisify } = require('util');
// const AdmZip = require('adm-zip');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');

// const unlinkAsync = promisify(fs.unlink);
// const rmdirAsync = promisify(fs.rm || fs.rmdir);

// const app = express();
// const PORT = process.env.PORT || 10000;

// // Configuration Validation (unchanged)
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:', missingVars);
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
// };
// validateConfig();

// // Rate Limiting (unchanged)
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100
// });
// app.use(limiter);

// // Redis Client Setup (unchanged)
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
//   }
// });

// redisClient.on('error', err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Client Error:', err.message);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });

// (async () => {
//   try {
//     await redisClient.connect();
//   } catch (err) {
//     console.error('Redis Connection Failed:', err.message);
//     sessionStore = new session.MemoryStore();
//   }
// })();

// // Middleware (unchanged)
// app.use(cors({
//   origin: (origin, callback) => {
//     const allowedOrigins = [
//       'https://aru-sdms.vercel.app',
//       'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app',
//       'https://aru-sdms-lmm221k5y-frevastramthecoders-projects.vercel.app'
//     ];
//     if (!origin || allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
// }));

// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
// app.use(passport.initialize());
// app.use(passport.session());

// // Root Route (unchanged)
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset' }
//   });
// });

// // Database Connection (unchanged)
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false }
// });

// pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

// const testDatabaseConnection = async () => {
//   const client = await pool.connect();
//   try {
//     const res = await client.query('SELECT NOW(), version()');
//     console.log('✅ Database connected:', res.rows[0].version);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//     return false;
//   } finally {
//     client.release();
//   }
// };

// // Auth Middleware (unchanged)
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', details: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // Email Transporter (unchanged)
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
// });
// transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// // OTP Generator (unchanged)
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // Passport Setup (unchanged)
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     done(null, res.rows[0] || false);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('No email in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const [newUser] = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   ).rows;
//   return newUser;
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// // Dataset Validation (unchanged)
// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation'
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   next();
// };

// // Dataset Routes (unchanged)
// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT id, properties FROM ${dataset} ORDER BY id ASC`);
//     res.json({ features: result.rows });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const result = await pool.query(`INSERT INTO ${dataset} (properties) VALUES ($1) RETURNING id, properties`, [properties]);
//     res.status(201).json({ message: 'Item uploaded!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const result = await pool.query(`UPDATE ${dataset} SET properties = $1 WHERE id = $2 RETURNING id, properties`, [properties, id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Updated!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM ${dataset} WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Shapefile Upload (unchanged)
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = path.join(__dirname, 'Uploads', 'shapefiles');
//     if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
//     cb(null, `${uniqueSuffix}-${file.originalname}`);
//   }
// });

// const fileFilter = (req, file, cb) => {
//   if (file.mimetype === 'application/zip' || file.originalname.match(/\.(zip)$/i)) {
//     cb(null, true);
//   } else {
//     cb(new Error('Only .zip files are allowed!'), false);
//   }
// };

// const upload = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } }).single('shapefile');

// app.post('/api/shapefile/upload', authenticate, (req, res) => {
//   upload(req, res, async (err) => {
//     if (err) {
//       return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.message });
//     }
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     const zipPath = req.file.path;
//     const unzipDir = path.join(path.dirname(zipPath), path.basename(zipPath, '.zip'));

//     try {
//       const zip = new AdmZip(zipPath);
//       zip.extractAllTo(unzipDir, true);

//       const files = fs.readdirSync(unzipDir);
//       const shpFile = files.find(f => f.toLowerCase().endsWith('.shp'));
//       if (!shpFile) throw new Error('No .shp file found in the ZIP');

//       const shpFilePath = path.join(unzipDir, shpFile);
//       const geojson = { type: 'FeatureCollection', features: [] };

//       const source = await shapefile.open(shpFilePath);
//       for await (const result of source) {
//         geojson.features.push({ type: 'Feature', geometry: result.geometry, properties: result.properties });
//       }

//       await unlinkAsync(zipPath);
//       await rmdirAsync(unzipDir, { recursive: true, force: true });

//       res.json({ message: 'Shapefile uploaded and processed', data: geojson });
//     } catch (error) {
//       await unlinkAsync(zipPath).catch(() => {});
//       await rmdirAsync(unzipDir, { recursive: true, force: true }).catch(() => {});
//       res.status(500).json({ error: error.message });
//     }
//   });
// });

// // Auth Routes
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
//     if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name.trim(), emailLower, hashedPassword, false, otp, 'user']
//     );

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Verify your account',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/verify-otp', async (req, res, next) => { // Renamed from /verify
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
//     res.json({ message: 'Email verified' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/resend-otp', async (req, res, next) => { // New route
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Resend Verification OTP',
//       text: `Your new OTP is: ${otp}`,
//       html: `<p>Your new OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'New OTP sent to your email' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out' });
//     });
//   });
// });

// app.post('/api/auth/reset-password-request', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Reset Password OTP',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'Reset password OTP sent' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/reset-password', async (req, res, next) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     const hashedPassword = await bcrypt.hash(newPassword, 12);
//     await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     next(err);
//   }
// });

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

//   app.get('/auth/google/callback',
//     passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
//     }
//   );
// }

// app.get('/api/health', async (req, res) => {
//   const dbStatus = await testDatabaseConnection();
//   res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
// });

// app.use((err, req, res, next) => {
//   console.error('Server Error:', err.stack);
//   res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
// });

// (async () => {
//   await testDatabaseConnection();
//   app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
// })();

// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');

// // Import shapefile upload route
// const shapefileUpload = require('./routes/shapefileUpload');

// const app = express();
// const PORT = process.env.PORT || 10000;

// // Configuration Validation
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:', missingVars);
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
// };
// validateConfig();

// // Rate Limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100
// });
// app.use(limiter);

// // Redis Client Setup
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
//   }
// });

// redisClient.on('error', err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Client Error:', err.message);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });

// (async () => {
//   try {
//     await redisClient.connect();
//   } catch (err) {
//     console.error('Redis Connection Failed:', err.message);
//     sessionStore = new session.MemoryStore();
//   }
// })();

// // Middleware
// app.use(cors({
//   origin: (origin, callback) => {
//     const allowedOrigins = [
//       'https://aru-sdms.vercel.app',
//       'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app',
//       'https://aru-sdms-lmm221k5y-frevastramthecoders-projects.vercel.app'
//     ];
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
// }));

// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
// app.use(passport.initialize());
// app.use(passport.session());

// // Database Connection
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false }
// });

// pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

// const testDatabaseConnection = async () => {
//   const client = await pool.connect();
//   try {
//     const res = await client.query('SELECT NOW(), version()');
//     console.log('✅ Database connected:', res.rows[0].version);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//     return false;
//   } finally {
//     client.release();
//   }
// };

// // Auth Middleware
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', details: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // Email Transporter
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
// });
// transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// // OTP Generator
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // Passport Setup
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     done(null, res.rows[0] || false);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('No email in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const newUser = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   );
//   return newUser.rows[0];
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// // Root Route
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset', upload: '/upload/:datasetType' }
//   });
// });

// // Dataset Validation
// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation', 'aruboundary'
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   next();
// };

// // Dataset Routes
// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT id, properties FROM ${dataset} ORDER BY id ASC`);
//     res.json({ features: result.rows });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const result = await pool.query(`INSERT INTO ${dataset} (properties) VALUES ($1) RETURNING id, properties`, [properties]);
//     res.status(201).json({ message: 'Item uploaded!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const result = await pool.query(`UPDATE ${dataset} SET properties = $1 WHERE id = $2 RETURNING id, properties`, [properties, id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Updated!', record: result.rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM ${dataset} WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Auth Routes
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
//     if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name.trim(), emailLower, hashedPassword, false, otp, 'user']
//     );

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Verify your account',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/verify-otp', async (req, res, next) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
//     res.json({ message: 'Email verified' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/resend-otp', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Resend Verification OTP',
//       text: `Your new OTP is: ${otp}`,
//       html: `<p>Your new OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'New OTP sent to your email' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out' });
//     });
//   });
// });

// app.post('/api/auth/reset-password-request', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Reset Password OTP',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'Reset password OTP sent' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/reset-password', async (req, res, next) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     const hashedPassword = await bcrypt.hash(newPassword, 12);
//     await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     next(err);
//   }
// });

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

//   app.get('/auth/google/callback',
//     passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
//     }
//   );
// }

// // Health Check
// app.get('/api/health', async (req, res) => {
//   const dbStatus = await testDatabaseConnection();
//   res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
// });

// // Mount shapefile upload route
// app.use('/upload', shapefileUpload);

// // Error Handling Middleware
// app.use((err, req, res, next) => {
//   console.error('Server Error:', err.stack);
//   res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
// });

// // Export pool and authenticate for use in routes
// module.exports = { pool, authenticate };

// (async () => {
//   await testDatabaseConnection();
//   app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
// })();

// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');

// // Import shapefile upload route
// const shapefileUpload = require('./routes/shapefile'); // Corrected to reference shapefile.js

// const app = express();
// const PORT = process.env.PORT || 10000;

// // Configuration Validation
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:', missingVars);
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
// };
// validateConfig();

// // Rate Limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100
// });
// app.use(limiter);

// // Redis Client Setup
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
//   }
// });

// redisClient.on('error', err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Client Error:', err.message);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });

// (async () => {
//   try {
//     await redisClient.connect();
//   } catch (err) {
//     console.error('Redis Connection Failed:', err.message);
//     sessionStore = new session.MemoryStore();
//   }
// })();

// // Middleware
// app.use(cors({
//   origin: (origin, callback) => {
//     const allowedOrigins = [
//       'https://aru-sdms.vercel.app',
//       'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app',
//       'https://aru-sdms-lmm221k5y-frevastramthecoders-projects.vercel.app'
//     ];
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
// }));

// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
// app.use(passport.initialize());
// app.use(passport.session());

// // Database Connection
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false }
// });

// pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

// const testDatabaseConnection = async () => {
//   const client = await pool.connect();
//   try {
//     const res = await client.query('SELECT NOW(), version()');
//     console.log('✅ Database connected:', res.rows[0].version);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//     return false;
//   } finally {
//     client.release();
//   }
// };

// // Auth Middleware
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', details: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // Email Transporter
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
// });
// transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// // OTP Generator
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // Passport Setup
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     done(null, res.rows[0] || false);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('No email in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const newUser = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   );
//   return newUser.rows[0];
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// // Root Route
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset', upload: '/upload/:datasetType' }
//   });
// });

// // Dataset Validation
// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation', 'aruboundary'
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   next();
// };

// // Dataset Routes
// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT * FROM "${dataset}" ORDER BY id ASC`);
//     const features = result.rows.map(row => {
//       const { id, geom, ...properties } = row;
//       return {
//         id,
//         properties,
//         geometry: geom ? JSON.parse(geom) : null
//       };
//     });
//     res.json({ features });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const keys = Object.keys(properties);
//     const values = Object.values(properties);
//     const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
//     const columns = keys.map(k => `"${k}"`).join(', ');
//     const result = await pool.query(
//       `INSERT INTO "${dataset}" (${columns}) VALUES (${placeholders}) RETURNING *`,
//       values
//     );
//     const { id, geom, ...recordProperties } = result.rows[0];
//     res.status(201).json({
//       message: 'Item uploaded!',
//       record: { id, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const keys = Object.keys(properties);
//     const values = Object.values(properties);
//     const setClause = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
//     const result = await pool.query(
//       `UPDATE "${dataset}" SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
//       [...values, id]
//     );
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     const { id: recordId, geom, ...recordProperties } = result.rows[0];
//     res.json({
//       message: 'Updated!',
//       record: { id: recordId, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM "${dataset}" WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Auth Routes
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
//     if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name.trim(), emailLower, hashedPassword, false, otp, 'user']
//     );

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Verify your account',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/verify-otp', async (req, res, next) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
//     res.json({ message: 'Email verified' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/resend-otp', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Resend Verification OTP',
//       text: `Your new OTP is: ${otp}`,
//       html: `<p>Your new OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'New OTP sent to your email' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out' });
//     });
//   });
// });

// app.post('/api/auth/reset-password-request', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Reset Password OTP',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'Reset password OTP sent' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/reset-password', async (req, res, next) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     const hashedPassword = await bcrypt.hash(newPassword, 12);
//     await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     next(err);
//   }
// });

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

//   app.get('/auth/google/callback',
//     passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//     (req, res) => {
//       const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//       res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
//     }
//   );
// }

// // Health Check
// app.get('/api/health', async (req, res) => {
//   const dbStatus = await testDatabaseConnection();
//   res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
// });

// // Mount shapefile upload route
// app.use('/upload', shapefileUpload);

// // Error Handling Middleware
// app.use((err, req, res, next) => {
//   console.error('Server Error:', err.stack);
//   res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
// });

// // Export pool and authenticate for use in routes
// module.exports = { pool, authenticate };

// (async () => {
//   await testDatabaseConnection();
//   app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
// })();

// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');

// const app = express();
// const PORT = process.env.PORT || 10000;

// // Configuration Validation
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:', missingVars);
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
// };
// validateConfig();

// // Rate Limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100
// });
// app.use(limiter);

// // Redis Client Setup
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
//   }
// });

// redisClient.on('error', err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Client Error:', err.message);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });

// (async () => {
//   try {
//     await redisClient.connect();
//   } catch (err) {
//     console.error('Redis Connection Failed:', err.message);
//     sessionStore = new session.MemoryStore();
//   }
// })();

// // Middleware
// app.use(cors({
//   origin: (origin, callback) => {
//     const allowedOrigins = [
//       'https://aru-sdms.vercel.app',
//       'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app',
//       'https://aru-sdms-lmm221k5y-frevastramthecoders-projects.vercel.app'
//     ];
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
// }));

// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
// app.use(passport.initialize());
// app.use(passport.session());

// // Database Connection
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false }
// });

// pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

// const testDatabaseConnection = async () => {
//   const client = await pool.connect();
//   try {
//     const res = await client.query('SELECT NOW(), version()');
//     console.log('✅ Database connected:', res.rows[0].version);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//     return false;
//   } finally {
//     client.release();
//   }
// };

// // Auth Middleware
// const authenticate = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', details: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // Email Transporter
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
// });
// transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// // OTP Generator
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // Passport Setup
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     done(null, res.rows[0] || false);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('No email in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const newUser = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   );
//   return newUser.rows[0];
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// // Root Route
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset', upload: '/upload/:datasetType' }
//   });
// });

// // Dataset Validation
// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation', 'aruboundary'
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   next();
// };

// // Dataset Routes
// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT * FROM "${dataset}" ORDER BY id ASC`);
//     const features = result.rows.map(row => {
//       const { id, geom, ...properties } = row;
//       return {
//         id,
//         properties,
//         geometry: geom ? JSON.parse(geom) : null
//       };
//     });
//     res.json({ features });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const keys = Object.keys(properties);
//     const values = Object.values(properties);
//     const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
//     const columns = keys.map(k => `"${k}"`).join(', ');
//     const result = await pool.query(
//       `INSERT INTO "${dataset}" (${columns}) VALUES (${placeholders}) RETURNING *`,
//       values
//     );
//     const { id, geom, ...recordProperties } = result.rows[0];
//     res.json({
//       message: 'Item uploaded!',
//       record: { id, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const keys = Object.keys(properties);
//     const values = Object.values(properties);
//     const setClause = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
//     const result = await pool.query(
//       `UPDATE "${dataset}" SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
//       [...values, id]
//     );
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     const { id: recordId, geom, ...recordProperties } = result.rows[0];
//     res.json({
//       message: 'Updated!',
//       record: { id: recordId, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM "${dataset}" WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Auth Routes
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
//     if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name.trim(), emailLower, hashedPassword, false, otp, 'user']
//     );

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Verify your account',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/verify-otp', async (req, res, next) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
//     res.json({ message: 'Email verified' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/resend-otp', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Resend Verification OTP',
//       text: `Your new OTP is: ${otp}`,
//       html: `<p>Your new OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'New OTP sent to your email' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out' });
//     });
//   });
// });

// app.post('/api/auth/reset-password-request', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Reset Password OTP',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'Reset password OTP sent' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/reset-password', async (req, res, next) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     const hashedPassword = await bcrypt.hash(newPassword, 12);
//     await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     next(err);
//   }
// });

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// app.get('/auth/google/callback',
//   passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//   (req, res) => {
//     const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
//   }
// );

// // Health Check
// app.get('/api/health', async (req, res) => {
//   const dbStatus = await testDatabaseConnection();
//   res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
// });

// // Import shapefile upload route after middleware definitions
// const shapefileUpload = require('./routes/shapefile');

// // Mount shapefile upload route
// app.use('/upload', shapefileUpload);

// // Error Handling Middleware
// app.use((err, req, res, next) => {
//   console.error('Server Error:', err.stack);
//   res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
// });

// // Export pool and authenticate for use in routes
// module.exports = { pool, authenticate };

// (async () => {
//   await testDatabaseConnection();
//   const server = app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
//   server.on('error', (err) => {
//     console.error('Server startup error:', err.message);
//     process.exit(1);
//   });
// })();
// const path = require('path');
// require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// const express = require('express');
// const cors = require('cors');
// const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
// const { Pool } = require('pg');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');

// const app = express();
// const PORT = process.env.PORT || 10000;

// // Configuration Validation
// const validateConfig = () => {
//   const requiredVars = [
//     'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
//     'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
//   ];
//   const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
//   const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

//   if (missingVars.length > 0) {
//     console.error('❌ Missing required environment variables:', missingVars);
//     process.exit(1);
//   }
//   console.log('✅ Environment variables validated successfully');
// };
// validateConfig();

// // Rate Limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100
// });
// app.use(limiter);

// // Redis Client Setup
// let sessionStore;
// let redisErrorLogged = false;

// const redisClient = createClient({
//   url: process.env.REDIS_URL,
//   socket: {
//     reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
//   }
// });

// redisClient.on('error', err => {
//   if (!redisErrorLogged) {
//     console.error('Redis Client Error:', err.message);
//     redisErrorLogged = true;
//     sessionStore = new session.MemoryStore();
//   }
// });
// redisClient.on('connect', () => console.log('Redis Client Connected'));
// redisClient.on('ready', () => {
//   console.log('Redis Client Ready');
//   sessionStore = new RedisStore({ client: redisClient });
//   redisErrorLogged = false;
// });

// (async () => {
//   try {
//     await redisClient.connect();
//   } catch (err) {
//     console.error('Redis Connection Failed:', err.message);
//     sessionStore = new session.MemoryStore();
//   }
// })();

// // Middleware
// app.use(cors({
//   origin: (origin, callback) => {
//     const allowedOrigins = [
//       'https://aru-sdms.vercel.app',
//       'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app',
//       'https://aru-sdms-lmm221k5y-frevastramthecoders-projects.vercel.app'
//     ];
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));

// app.use(session({
//   store: sessionStore,
//   secret: process.env.SESSION_SECRET.trim(),
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
// }));

// app.use(express.json({ limit: '50mb' }));
// app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
// app.use(passport.initialize());
// app.use(passport.session());

// // Database Connection
// const pool = new Pool({
//   user: process.env.DB_USER.trim(),
//   host: process.env.DB_HOST.trim(),
//   database: process.env.DB_NAME.trim(),
//   password: process.env.DB_PASS.trim(),
//   port: Number(process.env.DB_PORT),
//   ssl: { rejectUnauthorized: false }
// });

// pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

// const testDatabaseConnection = async () => {
//   const client = await pool.connect();
//   try {
//     const res = await client.query('SELECT NOW(), version()');
//     console.log('✅ Database connected:', res.rows[0].version);
//     return true;
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//     return false;
//   } finally {
//     client.release();
//   }
// };

// // Auth Middleware
// const authenticate = (req, res, next) => {
//   console.log('server.js: authenticate middleware called');
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Authentication required' });

//   const [bearer, token] = authHeader.split(' ');
//   if (bearer !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid token format' });

//   jwt.verify(token, process.env.JWT_SECRET.trim(), (err, decoded) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token', details: err.message });
//     req.user = decoded;
//     next();
//   });
// };

// const isAdmin = (req, res, next) => {
//   if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required' });
//   next();
// };

// // Email Transporter
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
// });
// transporter.verify((error) => error && console.error('❌ Email Transporter Error:', error));

// // OTP Generator
// const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// // Passport Setup
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => {
//   try {
//     const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//     done(null, res.rows[0] || false);
//   } catch (err) {
//     done(err, null);
//   }
// });

// async function findOrCreateUser(profile, provider) {
//   const email = profile.emails?.[0]?.value;
//   if (!email) throw new Error('No email in social profile');

//   const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//   if (rows.length > 0) return rows[0];

//   const name = profile.displayName || profile.username || 'No Name';
//   const newUser = await pool.query(
//     `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
//     [name, email, true, 'user', provider]
//   );
//   return newUser.rows[0];
// }

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// // Root Route
// app.get('/', (req, res) => {
//   res.json({
//     message: 'Welcome to the ARU-SDMS Backend API',
//     status: 'running',
//     version: '1.0.0',
//     endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset', upload: '/upload/:datasetType' }
//   });
// });

// // Dataset Validation
// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation', 'aruboundary'
// ];

// const validateDataset = (req, res, next) => {
//   const dataset = req.params.dataset;
//   if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
//   next();
// };

// // Dataset Routes
// app.get('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const result = await pool.query(`SELECT * FROM "${dataset}" ORDER BY id ASC`);
//     const features = result.rows.map(row => {
//       const { id, geom, ...properties } = row;
//       return {
//         id,
//         properties,
//         geometry: geom ? JSON.parse(geom) : null
//       };
//     });
//     res.json({ features });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/:dataset', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset } = req.params;
//     const properties = req.body;
//     const keys = Object.keys(properties);
//     const values = Object.values(properties);
//     const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
//     const columns = keys.map(k => `"${k}"`).join(', ');
//     const result = await pool.query(
//       `INSERT INTO "${dataset}" (${columns}) VALUES (${placeholders}) RETURNING *`,
//       values
//     );
//     const { id, geom, ...recordProperties } = result.rows[0];
//     res.json({
//       message: 'Item uploaded!',
//       record: { id, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const properties = req.body;
//     const keys = Object.keys(properties);
//     const values = Object.values(properties);
//     const setClause = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
//     const result = await pool.query(
//       `UPDATE "${dataset}" SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
//       [...values, id]
//     );
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     const { id: recordId, geom, ...recordProperties } = result.rows[0];
//     res.json({
//       message: 'Updated!',
//       record: { id: recordId, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
//     });
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/api/:dataset/:id', authenticate, validateDataset, async (req, res, next) => {
//   try {
//     const { dataset, id } = req.params;
//     const result = await pool.query(`DELETE FROM "${dataset}" WHERE id = $1`, [id]);
//     if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
//     res.json({ message: 'Deleted!' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Auth Routes
// app.post('/api/auth/register', async (req, res, next) => {
//   try {
//     const { name, email, password } = req.body;
//     if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email = $1', [emailLower]);
//     if (rowCount > 0) return res.status(409).json({ error: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);
//     const otp = generateOTP();

//     const { rows } = await pool.query(
//       `INSERT INTO users (name, email, password, is_verified, otp, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, is_verified`,
//       [name.trim(), emailLower, hashedPassword, false, otp, 'user']
//     );

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Verify your account',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.status(201).json({ message: 'Registered. Verify your email.', user: rows[0] });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/verify-otp', async (req, res, next) => {
//   try {
//     const { email, otp } = req.body;
//     if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp, is_verified FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.is_verified) return res.status(400).json({ error: 'Already verified' });
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     await pool.query('UPDATE users SET is_verified = true, otp = NULL WHERE id = $1', [user.id]);
//     res.json({ message: 'Email verified' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/resend-otp', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Resend Verification OTP',
//       text: `Your new OTP is: ${otp}`,
//       html: `<p>Your new OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'New OTP sent to your email' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/login', async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = rows[0];
//     if (!user.is_verified) return res.status(401).json({ error: 'Email not verified' });

//     const match = await bcrypt.compare(password, user.password);
//     if (!match) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/logout', (req, res) => {
//   req.logout(() => {
//     req.session.destroy(err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.clearCookie('connect.sid');
//       res.json({ message: 'Logged out' });
//     });
//   });
// });

// app.post('/api/auth/reset-password-request', async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: 'Email required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const otp = generateOTP();
//     await pool.query('UPDATE users SET otp = $1 WHERE id = $2', [otp, rows[0].id]);
//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: emailLower,
//       subject: 'Reset Password OTP',
//       text: `Your OTP is: ${otp}`,
//       html: `<p>Your OTP is: <strong>${otp}</strong></p>`
//     });

//     res.json({ message: 'Reset password OTP sent' });
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/api/auth/reset-password', async (req, res, next) => {
//   try {
//     const { email, otp, newPassword } = req.body;
//     if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required' });

//     const emailLower = email.toLowerCase().trim();
//     const { rows } = await pool.query('SELECT id, otp FROM users WHERE email = $1', [emailLower]);
//     if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

//     const user = rows[0];
//     if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

//     const hashedPassword = await bcrypt.hash(newPassword, 12);
//     await pool.query('UPDATE users SET password = $1, otp = NULL WHERE id = $2', [hashedPassword, user.id]);
//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     next(err);
//   }
// });

// if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && !process.env.GOOGLE_CLIENT_ID.startsWith('your_')) {
//   passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID.trim(),
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
//     callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
//   }, async (accessToken, refreshToken, profile, done) => {
//     try {
//       const user = await findOrCreateUser(profile, 'google');
//       done(null, user);
//     } catch (err) {
//       done(err, null);
//     }
//   }));
// }

// app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// app.get('/auth/google/callback',
//   passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
//   (req, res) => {
//     const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
//     res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
//   }
// );

// // Health Check
// app.get('/api/health', async (req, res) => {
//   const dbStatus = await testDatabaseConnection();
//   res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
// });

// // Import shapefile upload route after middleware definitions
// const shapefileUpload = require('./routes/shapefile');

// // Debug: Log to verify shapefile import
// console.log('server.js: typeof shapefileUpload:', typeof shapefileUpload);

// // Mount shapefile upload route
// app.use('/upload', shapefileUpload);

// // Error Handling Middleware
// app.use((err, req, res, next) => {
//   console.error('Server Error:', err.stack);
//   res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
// });

// // Export pool and authenticate for use in routes
// module.exports = { pool, authenticate };

// (async () => {
//   await testDatabaseConnection();
//   const server = app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
//   server.on('error', (err) => {
//     console.error('Server startup error:', err.message);
//     process.exit(1);
//   });
// })();

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;

// Configuration Validation
const validateConfig = () => {
  const requiredVars = [
    'JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_PASS', 'DB_HOST', 'DB_NAME', 'DB_PORT',
    'EMAIL_USER', 'EMAIL_PASS', 'CORS_ORIGIN', 'CLIENT_URL', 'SERVER_URL', 'REDIS_URL'
  ];
  const optionalVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
  const missingVars = requiredVars.filter(v => !process.env[v] || process.env[v].trim() === '');

  if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingVars);
    process.exit(1);
  }
  console.log('✅ Environment variables validated successfully');
};
validateConfig();

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Redis Client Setup
let sessionStore;
let redisErrorLogged = false;

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    reconnectStrategy: retries => (retries > 10 ? false : Math.min(retries * 100, 3000))
  }
});

redisClient.on('error', err => {
  if (!redisErrorLogged) {
    console.error('Redis Client Error:', err.message);
    redisErrorLogged = true;
    sessionStore = new session.MemoryStore();
  }
});
redisClient.on('connect', () => console.log('Redis Client Connected'));
redisClient.on('ready', () => {
  console.log('Redis Client Ready');
  sessionStore = new RedisStore({ client: redisClient });
  redisErrorLogged = false;
});

(async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error('Redis Connection Failed:', err.message);
    sessionStore = new session.MemoryStore();
  }
})();

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://aru-sdms.vercel.app',
      'https://aru-sdms-git-main-frevastramthecoders-projects.vercel.app',
      'https://aru-sdms-lmm221k5y-frevastramthecoders-projects.vercel.app'
    ];
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

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET.trim(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' }
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000 }));
app.use(passport.initialize());
app.use(passport.session());

// Database Connection
const pool = new Pool({
  user: process.env.DB_USER.trim(),
  host: process.env.DB_HOST.trim(),
  database: process.env.DB_NAME.trim(),
  password: process.env.DB_PASS.trim(),
  port: Number(process.env.DB_PORT),
  ssl: { rejectUnauthorized: false }
});

pool.on('error', (err, client) => console.error('PostgreSQL Pool Error:', err.message));

const testDatabaseConnection = async () => {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT NOW(), version()');
    console.log('✅ Database connected:', res.rows[0].version);
    return true;
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
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
  auth: { user: process.env.EMAIL_USER.trim(), pass: process.env.EMAIL_PASS.trim() },
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
  const email = profile.emails?.[0]?.value;
  if (!email) throw new Error('No email in social profile');

  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (rows.length > 0) return rows[0];

  const name = profile.displayName || profile.username || 'No Name';
  const newUser = await pool.query(
    `INSERT INTO users (name, email, is_verified, role, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [name, email, true, 'user', provider]
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
    endpoints: { health: '/api/health', auth: '/api/auth', datasets: '/api/:dataset', upload: '/upload/:datasetType' }
  });
});

// Dataset Validation
const VALID_DATASETS = [
  'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
  'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
  'parking', 'vegetation', 'aruboundary'
];

const validateDataset = (req, res, next) => {
  const dataset = req.params.dataset;
  if (!VALID_DATASETS.includes(dataset)) return res.status(400).json({ error: `Invalid dataset: ${dataset}` });
  next();
};

// Dataset Routes
const { authenticateToken } = require('./middleware/authMiddleware');

app.get('/api/:dataset', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    const result = await pool.query(`SELECT * FROM "${dataset}" ORDER BY id ASC`);
    const features = result.rows.map(row => {
      const { id, geom, ...properties } = row;
      return {
        id,
        properties,
        geometry: geom ? JSON.parse(geom) : null
      };
    });
    res.json({ features });
  } catch (err) {
    next(err);
  }
});

app.post('/api/:dataset', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset } = req.params;
    const properties = req.body;
    const keys = Object.keys(properties);
    const values = Object.values(properties);
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
    const columns = keys.map(k => `"${k}"`).join(', ');
    const result = await pool.query(
      `INSERT INTO "${dataset}" (${columns}) VALUES (${placeholders}) RETURNING *`,
      values
    );
    const { id, geom, ...recordProperties } = result.rows[0];
    res.json({
      message: 'Item uploaded!',
      record: { id, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
    });
  } catch (err) {
    next(err);
  }
});

app.put('/api/:dataset/:id', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset, id } = req.params;
    const properties = req.body;
    const keys = Object.keys(properties);
    const values = Object.values(properties);
    const setClause = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
    const result = await pool.query(
      `UPDATE "${dataset}" SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`,
      [...values, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
    const { id: recordId, geom, ...recordProperties } = result.rows[0];
    res.json({
      message: 'Updated!',
      record: { id: recordId, properties: recordProperties, geometry: geom ? JSON.parse(geom) : null }
    });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/:dataset/:id', authenticateToken, validateDataset, async (req, res, next) => {
  try {
    const { dataset, id } = req.params;
    const result = await pool.query(`DELETE FROM "${dataset}" WHERE id = $1`, [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Record not found' });
    res.json({ message: 'Deleted!' });
  } catch (err) {
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
    next(err);
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.logout(() => {
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
    next(err);
  }
});

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

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });
    res.redirect(`${process.env.CLIENT_URL}/social-login?token=${encodeURIComponent(token)}`);
  }
);

// Health Check
app.get('/api/health', async (req, res) => {
  const dbStatus = await testDatabaseConnection();
  res.json({ status: 'ok', database: dbStatus ? 'connected' : 'disconnected', serverTime: new Date() });
});

// Import shapefile upload route
const shapefileUpload = require('./routes/shapefile');

// Debug: Log to verify shapefile import
console.log('server.js: typeof shapefileUpload:', typeof shapefileUpload);

// Mount shapefile upload route
app.use('/upload', shapefileUpload);

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

// Export pool for use in routes
module.exports = { pool };

(async () => {
  await testDatabaseConnection();
  const server = app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  server.on('error', (err) => {
    console.error('Server startup error:', err.message);
    process.exit(1);
  });
})();