// // db.js
// const { Pool } = require('pg');

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

// module.exports = pool;

const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: Number(process.env.DB_PORT),
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20,
  allowExitOnIdle: true
});

pool.on('error', (err, client) => {
  console.error('PostgreSQL Pool Error:', err.stack);
});

pool.on('connect', () => {
  console.log('PostgreSQL Pool Connected');
});

module.exports = pool;