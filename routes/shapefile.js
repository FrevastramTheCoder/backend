// // routes/shapefileUpload.js

// const express = require('express');
// const fs = require('fs');
// const path = require('path');
// const multer = require('multer');
// const shapefile = require('shapefile');
// const AdmZip = require('adm-zip');
// const { Pool } = require('pg');
// const { promisify } = require('util');

// const router = express.Router();

// const unlink = promisify(fs.unlink);
// const rmdir = promisify(fs.rm || fs.rmdir);

// const pool = new Pool({
//   // Configure your DB here or rely on DATABASE_URL env variable
//   // connectionString: process.env.DATABASE_URL,
// });

// // Multer setup
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = path.join(__dirname, '..', 'uploads', 'shapefiles');
//     fs.mkdirSync(uploadDir, { recursive: true });
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
//     cb(null, `${uniqueSuffix}-${file.originalname}`);
//   }
// });

// const fileFilter = (req, file, cb) => {
//   const ext = path.extname(file.originalname).toLowerCase();
//   if (file.mimetype === 'application/zip' || ext === '.zip') {
//     cb(null, true);
//   } else {
//     cb(new Error('Only ZIP archives are allowed'), false);
//   }
// };

// const upload = multer({
//   storage,
//   fileFilter,
//   limits: { fileSize: 100 * 1024 * 1024 } // 100MB
// });

// // Whitelist valid dataset types (table names)
// const allowedDatasets = [
//   'roads',
//   'buildings',
//   'vegetation',
//   'footpaths',
//   'waterbodies',
//   // add your datasets here
// ];

// // Helper function to process shapefile and insert data
// async function processShapefile(datasetType, shpPath, dbfPath) {
//   if (!allowedDatasets.includes(datasetType)) {
//     throw new Error('Invalid dataset type');
//   }

//   const client = await pool.connect();
//   try {
//     await client.query('BEGIN');
//     await client.query('CREATE EXTENSION IF NOT EXISTS postgis');

//     const source = await shapefile.open(shpPath, dbfPath);
//     let result = await source.read();
//     if (result.done) throw new Error('Shapefile contains no features');

//     const firstFeature = result.value;
//     const propKeys = Object.keys(firstFeature.properties || {});

//     // Create table dynamically
//     const columnDefs = propKeys.map(k => `"${k}" TEXT`).join(', ');

//     await client.query(`
//       CREATE TABLE IF NOT EXISTS "${datasetType}" (
//         id SERIAL PRIMARY KEY,
//         ${columnDefs},
//         geom GEOMETRY(GEOMETRY, 4326)
//       )
//     `);

//     await client.query(`CREATE INDEX IF NOT EXISTS idx_${datasetType}_geom ON "${datasetType}" USING GIST (geom)`);

//     const insertQuery = `
//       INSERT INTO "${datasetType}" (${propKeys.map(k => `"${k}"`).join(', ')}, geom)
//       VALUES (${propKeys.map((_, i) => `$${i + 1}`).join(', ')}, ST_GeomFromGeoJSON($${propKeys.length + 1}))
//     `;

//     let featuresProcessed = 0;

//     while (!result.done) {
//       const feature = result.value;
//       if (!feature || !feature.geometry) {
//         result = await source.read();
//         continue;
//       }

//       const values = [
//         ...propKeys.map(k => feature.properties[k] ?? null),
//         JSON.stringify(feature.geometry)
//       ];

//       await client.query(insertQuery, values);
//       featuresProcessed++;
//       result = await source.read();
//     }

//     await client.query('COMMIT');
//     return featuresProcessed;
//   } catch (err) {
//     await client.query('ROLLBACK');
//     throw err;
//   } finally {
//     client.release();
//   }
// }

// // Utility: recursively list files
// function walkSync(dir, filelist = []) {
//   const files = fs.readdirSync(dir);
//   files.forEach((file) => {
//     const filepath = path.join(dir, file);
//     const stat = fs.statSync(filepath);
//     if (stat.isDirectory()) {
//       walkSync(filepath, filelist);
//     } else {
//       filelist.push(filepath);
//     }
//   });
//   return filelist;
// }

// // Upload route
// router.post('/:datasetType', upload.single('file'), async (req, res) => {
//   if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//   const { datasetType } = req.params;
//   const zipPath = req.file.path;
//   const extractDir = path.join(path.dirname(zipPath), `extracted_${Date.now()}`);

//   try {
//     fs.mkdirSync(extractDir, { recursive: true });
//     const zip = new AdmZip(zipPath);
//     zip.extractAllTo(extractDir, true);

//     const extractedFiles = walkSync(extractDir);

//     const shpPath = extractedFiles.find(f => f.toLowerCase().endsWith('.shp'));
//     const dbfPath = extractedFiles.find(f => f.toLowerCase().endsWith('.dbf'));
//     const shxExists = extractedFiles.some(f => f.toLowerCase().endsWith('.shx'));

//     if (!shpPath || !dbfPath || !shxExists) {
//       throw new Error('Missing .shp, .shx, or .dbf file in ZIP');
//     }

//     const featuresProcessed = await processShapefile(datasetType, shpPath, dbfPath);

//     await unlink(zipPath);
//     await rmdir(extractDir, { recursive: true });

//     res.json({
//       success: true,
//       message: `Successfully processed ${featuresProcessed} features`,
//       dataset: datasetType
//     });
//   } catch (err) {
//     console.error('Upload error:', err);

//     try {
//       if (fs.existsSync(zipPath)) await unlink(zipPath);
//       if (fs.existsSync(extractDir)) await rmdir(extractDir, { recursive: true });
//     } catch (cleanupErr) {
//       console.error('Cleanup failed:', cleanupErr);
//     }

//     res.status(500).json({
//       error: 'Failed to process shapefile',
//       details: err.message
//     });
//   }
// });

// module.exports = router;

const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const shapefile = require('shapefile');
const AdmZip = require('adm-zip');
const { promisify } = require('util');

const router = express.Router();

// Import pool and authenticate from main server
const { pool, authenticate } = require('../server'); // Adjust path to your main server file

const unlink = promisify(fs.unlink);
const rmdir = promisify(fs.rm || fs.rmdir);

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', 'Uploads', 'shapefiles');
    fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (file.mimetype === 'application/zip' || ext === '.zip') {
    cb(null, true);
  } else {
    cb(new Error('Only ZIP archives are allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// Whitelist valid dataset types (table names)
const allowedDatasets = [
  'buildings',
  'footpaths',
  'electricitySupply',
  'securityLights',
  'roads',
  'drainageSystems',
  'recreationalAreas',
  'vimbweta',
  'solidWasteCollection',
  'parking',
  'vegetation',
  'aruboundary'
];

// Helper function to process shapefile and insert data
async function processShapefile(datasetType, shpPath, dbfPath) {
  if (!allowedDatasets.includes(datasetType)) {
    throw new Error('Invalid dataset type');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('CREATE EXTENSION IF NOT EXISTS postgis');

    const source = await shapefile.open(shpPath, dbfPath);
    let result = await source.read();
    if (result.done) throw new Error('Shapefile contains no features');

    const firstFeature = result.value;
    const propKeys = Object.keys(firstFeature.properties || {});

    // Create table dynamically
    const columnDefs = propKeys.map(k => `"${k}" TEXT`).join(', ');

    await client.query(`
      CREATE TABLE IF NOT EXISTS "${datasetType}" (
        id SERIAL PRIMARY KEY,
        ${columnDefs},
        geom GEOMETRY(GEOMETRY, 4326)
      )
    `);

    await client.query(`CREATE INDEX IF NOT EXISTS idx_${datasetType}_geom ON "${datasetType}" USING GIST (geom)`);

    const insertQuery = `
      INSERT INTO "${datasetType}" (${propKeys.map(k => `"${k}"`).join(', ')}, geom)
      VALUES (${propKeys.map((_, i) => `$${i + 1}`).join(', ')}, ST_GeomFromGeoJSON($${propKeys.length + 1}))
    `;

    let featuresProcessed = 0;

    while (!result.done) {
      const feature = result.value;
      if (!feature || !feature.geometry) {
        result = await source.read();
        continue;
      }

      const values = [
        ...propKeys.map(k => feature.properties[k] ?? null),
        JSON.stringify(feature.geometry)
      ];

      await client.query(insertQuery, values);
      featuresProcessed++;
      result = await source.read();
    }

    await client.query('COMMIT');
    return featuresProcessed;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// Utility: recursively list files
function walkSync(dir, filelist = []) {
  const files = fs.readdirSync(dir);
  files.forEach((file) => {
    const filepath = path.join(dir, file);
    const stat = fs.statSync(filepath);
    if (stat.isDirectory()) {
      walkSync(filepath, filelist);
    } else {
      filelist.push(filepath);
    }
  });
  return filelist;
}

// Upload route
router.post('/:datasetType', authenticate, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const { datasetType } = req.params;
  const zipPath = req.file.path;
  const extractDir = path.join(path.dirname(zipPath), `extracted_${Date.now()}`);

  try {
    fs.mkdirSync(extractDir, { recursive: true });
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractDir, true);

    const extractedFiles = walkSync(extractDir);

    const shpPath = extractedFiles.find(f => f.toLowerCase().endsWith('.shp'));
    const dbfPath = extractedFiles.find(f => f.toLowerCase().endsWith('.dbf'));
    const shxExists = extractedFiles.some(f => f.toLowerCase().endsWith('.shx'));

    if (!shpPath || !dbfPath || !shxExists) {
      throw new Error('Missing .shp, .shx, or .dbf file in ZIP');
    }

    const featuresProcessed = await processShapefile(datasetType, shpPath, dbfPath);

    await unlink(zipPath);
    await rmdir(extractDir, { recursive: true });

    res.json({
      success: true,
      message: `Successfully processed ${featuresProcessed} features`,
      dataset: datasetType
    });
  } catch (err) {
    console.error('Upload error:', err);

    try {
      if (fs.existsSync(zipPath)) await unlink(zipPath);
      if (fs.existsSync(extractDir)) await rmdir(extractDir, { recursive: true });
    } catch (cleanupErr) {
      console.error('Cleanup failed:', cleanupErr);
    }

    res.status(500).json({
      error: 'Failed to process shapefile',
      details: err.message
    });
  }
});

module.exports = router;