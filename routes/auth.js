// // const express = require('express');
// // const router = express.Router();
// // const bcrypt = require('bcryptjs');
// // const jwt = require('jsonwebtoken');
// // const User = require('../models/User'); // your User mongoose model or ORM model
// // const { check, validationResult } = require('express-validator');

// // const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';
// // const JWT_EXPIRES_IN = '15m';
// // const JWT_REFRESH_EXPIRES_IN = '7d';

// // let refreshTokens = []; // For demo; store refresh tokens in DB in production

// // // Register
// // router.post('/register', [
// //   check('name').notEmpty(),
// //   check('email').isEmail(),
// //   check('password').isLength({ min: 6 }),
// // ], async (req, res) => {
// //   const errors = validationResult(req);
// //   if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

// //   const { name, email, password, role } = req.body;
// //   try {
// //     let user = await User.findOne({ email });
// //     if (user) return res.status(409).json({ message: 'User already exists' });

// //     const hashedPassword = await bcrypt.hash(password, 12);
// //     user = new User({ name, email, password: hashedPassword, role: role || 'user' });
// //     await user.save();

// //     const accessToken = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
// //     const refreshToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
// //     refreshTokens.push(refreshToken);

// //     res.status(201).json({
// //       user: { id: user.id, name: user.name, email: user.email, role: user.role },
// //       token: accessToken,
// //       refreshToken,
// //     });
// //   } catch (err) {
// //     console.error(err);
// //     res.status(500).json({ message: 'Server error' });
// //   }
// // });

// // // Login
// // router.post('/login', [
// //   check('email').isEmail(),
// //   check('password').exists(),
// // ], async (req, res) => {
// //   const errors = validationResult(req);
// //   if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

// //   const { email, password } = req.body;
// //   try {
// //     const user = await User.findOne({ email });
// //     if (!user) return res.status(401).json({ message: 'Invalid credentials' });

// //     const isMatch = await bcrypt.compare(password, user.password);
// //     if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

// //     const accessToken = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
// //     const refreshToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
// //     refreshTokens.push(refreshToken);

// //     res.json({
// //       user: { id: user.id, name: user.name, email: user.email, role: user.role },
// //       token: accessToken,
// //       refreshToken,
// //     });
// //   } catch (err) {
// //     console.error(err);
// //     res.status(500).json({ message: 'Server error' });
// //   }
// // });

// // // Token refresh endpoint
// // router.post('/token', (req, res) => {
// //   const { token } = req.body;
// //   if (!token) return res.status(401).json({ message: 'Refresh token required' });
// //   if (!refreshTokens.includes(token)) return res.status(403).json({ message: 'Invalid refresh token' });

// //   jwt.verify(token, JWT_SECRET, (err, user) => {
// //     if (err) return res.status(403).json({ message: 'Invalid refresh token' });
// //     const accessToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
// //     res.json({ token: accessToken });
// //   });
// // });

// // // Logout - revoke refresh token
// // router.post('/logout', (req, res) => {
// //   const { token } = req.body;
// //   refreshTokens = refreshTokens.filter(t => t !== token);
// //   res.status(204).send();
// // });

// // module.exports = router;


// const express = require('express');
// const router = express.Router();
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const { check, validationResult } = require('express-validator');
// const User = require('../models/User'); // Make sure this path is correct

// // ENV variables or default values
// const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';
// const JWT_EXPIRES_IN = '15m';
// const JWT_REFRESH_EXPIRES_IN = '7d';

// // In-memory refresh token store (replace with DB for production)
// let refreshTokens = [];

// /**
//  * @route   POST /api/auth/register
//  * @desc    Register a new user
//  */
// router.post('/register', [
//   check('name').notEmpty().withMessage('Name is required'),
//   check('email').isEmail().withMessage('Valid email is required'),
//   check('password').isLength({ min: 6 }).withMessage('Password must be 6+ characters'),
// ], async (req, res) => {
//   const errors = validationResult(req);
//   if (!errors.isEmpty())
//     return res.status(400).json({ errors: errors.array() });

//   const { name, email, password, role } = req.body;

//   try {
//     let existingUser = await User.findOne({ email });
//     if (existingUser)
//       return res.status(409).json({ message: 'User already exists' });

//     const hashedPassword = await bcrypt.hash(password, 12);

//     const user = new User({
//       name,
//       email,
//       password: hashedPassword,
//       role: role || 'user',
//     });

//     await user.save();

//     const payload = { id: user._id, role: user.role };

//     const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
//     const refreshToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
//     refreshTokens.push(refreshToken);

//     res.status(201).json({
//       user: { id: user._id, name: user.name, email: user.email, role: user.role },
//       token: accessToken,
//       refreshToken,
//     });
//   } catch (err) {
//     console.error('Register error:', err.message);
//     res.status(500).json({ message: 'Server error' });
//   }
// });

// /**
//  * @route   POST /api/auth/login
//  * @desc    Login user and return JWTs
//  */
// router.post('/login', [
//   check('email').isEmail().withMessage('Valid email is required'),
//   check('password').notEmpty().withMessage('Password is required'),
// ], async (req, res) => {
//   const errors = validationResult(req);
//   if (!errors.isEmpty())
//     return res.status(400).json({ errors: errors.array() });

//   const { email, password } = req.body;

//   try {
//     const user = await User.findOne({ email });
//     if (!user)
//       return res.status(401).json({ message: 'Invalid credentials' });

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch)
//       return res.status(401).json({ message: 'Invalid credentials' });

//     const payload = { id: user._id, role: user.role };

//     const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
//     const refreshToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
//     refreshTokens.push(refreshToken);

//     res.json({
//       user: { id: user._id, name: user.name, email: user.email, role: user.role },
//       token: accessToken,
//       refreshToken,
//     });
//   } catch (err) {
//     console.error('Login error:', err.message);
//     res.status(500).json({ message: 'Server error' });
//   }
// });

// /**
//  * @route   POST /api/auth/token
//  * @desc    Refresh access token
//  */
// router.post('/token', (req, res) => {
//   const { token } = req.body;
//   if (!token)
//     return res.status(401).json({ message: 'Refresh token required' });

//   if (!refreshTokens.includes(token))
//     return res.status(403).json({ message: 'Invalid refresh token' });

//   try {
//     const userData = jwt.verify(token, JWT_SECRET);
//     const newAccessToken = jwt.sign({ id: userData.id }, JWT_SECRET, {
//       expiresIn: JWT_EXPIRES_IN,
//     });

//     res.json({ token: newAccessToken });
//   } catch (err) {
//     console.error('Token refresh error:', err.message);
//     res.status(403).json({ message: 'Invalid token' });
//   }
// });

// /**
//  * @route   POST /api/auth/logout
//  * @desc    Revoke refresh token
//  */
// router.post('/logout', (req, res) => {
//   const { token } = req.body;
//   refreshTokens = refreshTokens.filter(t => t !== token);
//   res.status(204).send();
// });

// module.exports = router;


const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db'); // <-- you can export pool from your main file or put this logic here

const JWT_SECRET = process.env.JWT_SECRET;

// Register route
router.post('/register', async (req, res, next) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(409).json({ error: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      `INSERT INTO users (name, email, password, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role`,
      [name, email, hashedPassword, role]
    );

    const token = jwt.sign(
      {
        id: newUser.rows[0].id,
        role: newUser.rows[0].role,
        email: newUser.rows[0].email
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      user: newUser.rows[0],
      token
    });

  } catch (err) {
    console.error('Register error:', err);
    next(err);
  }
});

module.exports = router;
