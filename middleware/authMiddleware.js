
// // const jwt = require('jsonwebtoken');

// // function authenticateToken(req, res, next) {
// //   const authHeader = req.headers['authorization'];
// //   if (!authHeader) return res.status(401).json({ message: 'No token provided' });

// //   const tokenParts = authHeader.split(' ');
// //   if (tokenParts.length !== 2 || tokenParts[0].toLowerCase() !== 'bearer') {
// //     return res.status(401).json({ message: 'Invalid token format' });
// //   }

// //   const token = tokenParts[1];
// //   if (!token) return res.status(401).json({ message: 'No token provided' });

// //   const secret = process.env.JWT_SECRET;
// //   if (!secret) {
// //     return res.status(500).json({ message: 'Server configuration error' });
// //   }

// //   jwt.verify(token, secret, (err, user) => {
// //     if (err) {
// //       if (err.name === 'TokenExpiredError') {
// //         return res.status(401).json({ message: 'Token expired' });
// //       }
// //       return res.status(403).json({ message: 'Invalid token', error: err.message });
// //     }
// //     req.user = user;
// //     next();
// //   });
// // }

// // module.exports = { authenticateToken };

// const jwt = require('jsonwebtoken');

// function authenticateToken(req, res, next) {
//   console.log('authMiddleware.js: authenticateToken middleware called');
//   const authHeader = req.headers['authorization'];
//   if (!authHeader) return res.status(401).json({ message: 'No token provided' });

//   const tokenParts = authHeader.split(' ');
//   if (tokenParts.length !== 2 || tokenParts[0].toLowerCase() !== 'bearer') {
//     return res.status(401).json({ message: 'Invalid token format' });
//   }

//   const token = tokenParts[1];
//   if (!token) return res.status(401).json({ message: 'No token provided' });

//   const secret = process.env.JWT_SECRET ? process.env.JWT_SECRET.trim() : null;
//   if (!secret) {
//     return res.status(500).json({ message: 'Server configuration error' });
//   }

//   jwt.verify(token, secret, (err, user) => {
//     if (err) {
//       if (err.name === 'TokenExpiredError') {
//         return res.status(401).json({ message: 'Token expired' });
//       }
//       return res.status(403).json({ message: 'Invalid token', error: err.message });
//     }
//     req.user = user;
//     next();
//   });
// }

// module.exports = { authenticateToken };

const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  console.log('authMiddleware.js: authenticateToken middleware called');
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const tokenParts = authHeader.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({ message: 'Invalid token format' });
  }

  const token = tokenParts[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  const secret = process.env.JWT_SECRET ? process.env.JWT_SECRET.trim() : null;
  if (!secret) {
    return res.status(500).json({ message: 'Server configuration error' });
  }

  jwt.verify(token, secret, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token expired' });
      }
      return res.status(403).json({ message: 'Invalid token', error: err.message });
    }
    req.user = user;
    next();
  });
}

module.exports = { authenticateToken };