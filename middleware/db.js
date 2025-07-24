const { Pool } = require('pg');
require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: Number(process.env.DB_PORT),
  ssl: { rejectUnauthorized: false }, // Compatible with Render PostgreSQL
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20,
  allowExitOnIdle: true,
});

pool.on('connect', () => {
  console.log('✅ PostgreSQL Pool Connected');
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL Pool Error:', err.stack);
});

// Test connection on startup
(async () => {
  try {
    const client = await pool.connect();
    await client.query('SELECT NOW()');
    console.log('✅ Database connection test successful');
    client.release();
  } catch (err) {
    console.error('❌ Database connection test failed:', err.stack);
  }
})();

module.exports = pool;