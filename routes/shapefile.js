// const express = require('express');
// const fs = require('fs');
// const path = require('path');
// const multer = require('multer');
// const shapefile = require('shapefile');
// const AdmZip = require('adm-zip');
// const { promisify } = require('util');

// const router = express.Router();
// const { authenticateToken } = require('../middleware/authMiddleware');
// const pool = require('../middleware/db');

// // Debug: Log to verify imports
// console.log('shapefile.js: typeof router.post:', typeof router.post);
// console.log('shapefile.js: typeof authenticateToken:', typeof authenticateToken);
// console.log('shapefile.js: typeof pool:', typeof pool);

// const unlink = promisify(fs.unlink);
// const rmdir = promisify(fs.rm || fs.rmdir);

// // Multer setup
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = path.join(__dirname, '..', 'Uploads', 'shapefiles');
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
//   'buildings',
//   'footpaths',
//   'electricitySupply',
//   'securityLights',
//   'roads',
//   'drainageSystems',
//   'recreationalAreas',
//   'vimbweta',
//   'solidWasteCollection',
//   'parking',
//   'vegetation',
//   'aruboundary'
// ];

// // Helper function to process shapefile and insert data
// async function processShapefile(datasetType, shpPath, dbfPath) {
//   if (!allowedDatasets.includes(datasetType)) {
//     throw new Error('Invalid dataset type');
//   }

//   const client = await pool.connect();
//   try {
//     await client.query('BEGIN');
//     console.log('shapefile.js: Attempting to create PostGIS extension');
//     await client.query('CREATE EXTENSION IF NOT EXISTS postgis');

//     const source = await shapefile.open(shpPath, dbfPath);
//     console.log('shapefile.js: Shapefile opened successfully');
//     let result = await source.read();
//     if (result.done) throw new Error('Shapefile contains no features');

//     const firstFeature = result.value;
//     const propKeys = Object.keys(firstFeature.properties || {});
//     console.log('shapefile.js: Feature properties:', propKeys);

//     // Create table dynamically
//     const columnDefs = propKeys.map(k => `"${k}" TEXT`).join(', ');
//     await client.query(`
//       CREATE TABLE IF NOT EXISTS "${datasetType}" (
//         id SERIAL PRIMARY KEY,
//         ${columnDefs},
//         geom GEOMETRY(GEOMETRY, 4326)
//       )
//     `);
//     console.log(`shapefile.js: Table "${datasetType}" created or exists`);

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
//     console.log(`shapefile.js: Processed ${featuresProcessed} features for ${datasetType}`);
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
// router.post('/:datasetType', authenticateToken, upload.single('file'), async (req, res) => {
//   if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//   const { datasetType } = req.params;
//   const zipPath = req.file.path;
//   const extractDir = path.join(path.dirname(zipPath), `extracted_${Date.now()}`);

//   try {
//     console.log(`shapefile.js: Processing upload for datasetType: ${datasetType}, file: ${req.file.originalname}`);
//     fs.mkdirSync(extractDir, { recursive: true });
//     const zip = new AdmZip(zipPath);
//     zip.extractAllTo(extractDir, true);

//     const extractedFiles = walkSync(extractDir);
//     console.log('shapefile.js: Extracted files:', extractedFiles);

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
//     console.error('shapefile.js: Upload error:', err.stack);
//     try {
//       if (fs.existsSync(zipPath)) await unlink(zipPath);
//       if (fs.existsSync(extractDir)) await rmdir(extractDir, { recursive: true });
//     } catch (cleanupErr) {
//       console.error('shapefile.js: Cleanup error:', cleanupErr.stack);
//     }

//     res.status(500).json({
//       error: 'Failed to process shapefile',
//       details: err.message
//     });
//   }
// });

// module.exports = router;

// const express = require('express');
// const multer = require('multer');
// const shapefile = require('shapefile');
// const fs = require('fs').promises;
// const path = require('path');
// const AdmZip = require('adm-zip');
// const { Pool } = require('pg');
// const pool = require('../middleware/db');
// const { authenticateToken } = require('../middleware/authMiddleware');
// const proj4 = require('proj4');

// const router = express.Router();

// console.log('shapefile.js: typeof router.post:', typeof router.post);
// console.log('shapefile.js: typeof authenticateToken:', typeof authenticateToken);
// console.log('shapefile.js: typeof pool:', typeof pool);

// const VALID_DATASETS = [
//   'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
//   'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
//   'parking', 'vegetation', 'aruboundary'
// ];

// const upload = multer({ dest: 'uploads/' });

// const processShapefile = async (filePath, datasetType) => {
//   try {
//     console.log(`shapefile.js: Processing upload for datasetType: ${datasetType}, file: ${filePath}`);

//     const zip = new AdmZip(filePath);
//     const zipEntries = zip.getEntries();
//     let shpPath, dbfPath, prjPath;

//     for (const entry of zipEntries) {
//       if (entry.entryName.match(/\.shp$/i)) shpPath = entry.entryName;
//       if (entry.entryName.match(/\.dbf$/i)) dbfPath = entry.entryName;
//       if (entry.entryName.match(/\.prj$/i)) prjPath = entry.entryName;
//     }

//     if (!shpPath || !dbfPath) {
//       throw new Error('Missing .shp or .dbf file in ZIP');
//     }

//     const extractPath = path.join(__dirname, '../uploads', datasetType);
//     await fs.mkdir(extractPath, { recursive: true });
//     zip.extractAllTo(extractPath, true);

//     const shpFullPath = path.join(extractPath, shpPath);
//     const dbfFullPath = path.join(extractPath, dbfPath);
//     const prjFullPath = prjPath ? path.join(extractPath, prjPath) : null;

//     console.log(`shapefile.js: Extracted shapefile to ${shpFullPath}, dbf to ${dbfFullPath}, prj: ${prjFullPath || 'none'}`);

//     const source = await shapefile.open(shpFullPath, dbfFullPath);
//     let sourcePrj = prjFullPath ? await fs.readFile(prjFullPath, 'utf8') : null;
//     let featureCount = 0;
//     let record;

//     const targetCRS = 'EPSG:4326';
//     let sourceCRS = sourcePrj ? proj4.defs(sourcePrj) : null;

//     if (!sourceCRS) {
//       console.warn('shapefile.js: No .prj file found, assuming EPSG:4326. Verify input CRS manually if issues persist!');
//       sourceCRS = 'EPSG:4326';
//     } else {
//       console.log(`shapefile.js: Detected source CRS definition: ${sourcePrj}`);
//     }

//     const client = await pool.connect();

//     try {
//       await client.query('CREATE EXTENSION IF NOT EXISTS postgis');
//       console.log('shapefile.js: PostGIS extension enabled');

//       await client.query(`
//         CREATE TABLE IF NOT EXISTS "${datasetType}" (
//           id SERIAL PRIMARY KEY,
//           geom GEOMETRY(Geometry, 4326)
//         )
//       `);
//       console.log(`shapefile.js: Table ${datasetType} ensured with PostGIS geometry`);

//       while ((record = await source.read()) && !record.done) {
//         let geojson = record.value;
//         if (!geojson.geometry || !geojson.geometry.coordinates || !Array.isArray(geojson.geometry.coordinates)) {
//           console.warn(`shapefile.js: Skipping invalid geometry for feature ${featureCount + 1}:`, JSON.stringify(geojson).slice(0, 100));
//           continue;
//         }

//         console.log(`shapefile.js: Processing feature ${featureCount + 1}:`, JSON.stringify(geojson).slice(0, 100));

//         if (sourceCRS !== 'EPSG:4326') {
//           try {
//             geojson.geometry.coordinates = proj4(sourceCRS, targetCRS, geojson.geometry.coordinates);
//             console.log(`shapefile.js: Reprojected coordinates to ${targetCRS}:`, geojson.geometry.coordinates);
//           } catch (projErr) {
//             console.error(`shapefile.js: Projection error for feature ${featureCount + 1}:`, projErr.stack);
//             continue;
//           }
//         }

//         try {
//           await client.query(
//             `INSERT INTO "${datasetType}" (geom) VALUES (ST_GeomFromGeoJSON($1))`,
//             [JSON.stringify({ type: geojson.geometry.type, coordinates: geojson.geometry.coordinates })]
//           );
//           featureCount++;
//         } catch (dbErr) {
//           console.error(`shapefile.js: Database insert error for feature ${featureCount + 1}:`, dbErr.stack);
//         }
//       }

//       if (featureCount === 0) {
//         throw new Error('No valid features processed');
//       }

//       console.log(`shapefile.js: Successfully processed ${featureCount} features for ${datasetType}`);
//       return featureCount;
//     } finally {
//       client.release();
//       await fs.rm(extractPath, { recursive: true, force: true }).catch(err => console.warn('Cleanup failed:', err.stack));
//       console.log(`shapefile.js: Cleaned up ${extractPath}`);
//     }
//   } catch (err) {
//     console.error('shapefile.js: Upload error:', err.stack);
//     throw err;
//   }
// };

// router.post('/:datasetType', authenticateToken, upload.single('file'), async (req, res) => {
//   const { datasetType } = req.params;
//   console.log(`shapefile.js: Received upload request for datasetType: ${datasetType}`);

//   if (!VALID_DATASETS.includes(datasetType)) {
//     console.log(`shapefile.js: Invalid datasetType: ${datasetType}`);
//     return res.status(400).json({ error: `Invalid dataset type: ${datasetType}` });
//   }

//   if (!req.file) {
//     console.log('shapefile.js: No file uploaded');
//     return res.status(400).json({ error: 'No file uploaded' });
//   }

//   try {
//     const featureCount = await processShapefile(req.file.path, datasetType);
//     await fs.unlink(req.file.path);
//     console.log(`shapefile.js: Deleted uploaded file ${req.file.path}`);
//     res.json({ success: true, message: `Successfully processed ${featureCount} features`, dataset: datasetType });
//   } catch (err) {
//     console.error('shapefile.js: Upload error:', err.stack);
//     res.status(500).json({ error: 'Failed to process shapefile', details: err.message });
//   }
// });

// module.exports = router;

const express = require('express');
const multer = require('multer');
const shapefile = require('shapefile');
const fs = require('fs').promises;
const path = require('path');
const AdmZip = require('adm-zip');
const { Pool } = require('pg');
const pool = require('../middleware/db');
const { authenticateToken } = require('../middleware/authMiddleware');
const proj4 = require('proj4');

const router = express.Router();

const VALID_DATASETS = [
  'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
  'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
  'parking', 'vegetation', 'aruboundary'
];

const upload = multer({ dest: 'uploads/' });

const detectCRS = async (extractPath, prjPath) => {
  if (prjPath) {
    const prjContent = await fs.readFile(path.join(extractPath, prjPath), 'utf8');
    try {
      const epsgMatch = prjContent.match(/EPSG[:\d]+/);
      if (epsgMatch) return epsgMatch[0].replace(':', '');
      return proj4.defs(prjContent) ? prjContent : 'EPSG:32737'; // Default to UTM 37S if custom CRS fails
    } catch (err) {
      console.warn('Failed to parse .prj, defaulting to EPSG:32737:', err.message);
      return 'EPSG:32737';
    }
  }
  console.warn('No .prj file found, defaulting to EPSG:32737');
  return 'EPSG:32737';
};

const processShapefile = async (filePath, datasetType) => {
  try {
    const zip = new AdmZip(filePath);
    const zipEntries = zip.getEntries();
    let shpPath, dbfPath, prjPath;

    for (const entry of zipEntries) {
      if (entry.entryName.match(/\.shp$/i)) shpPath = entry.entryName;
      if (entry.entryName.match(/\.dbf$/i)) dbfPath = entry.entryName;
      if (entry.entryName.match(/\.prj$/i)) prjPath = entry.entryName;
    }

    if (!shpPath || !dbfPath) {
      throw new Error('Missing .shp or .dbf file in ZIP');
    }

    const extractPath = path.join(__dirname, '../uploads', datasetType);
    await fs.mkdir(extractPath, { recursive: true });
    zip.extractAllTo(extractPath, true);

    const shpFullPath = path.join(extractPath, shpPath);
    const dbfFullPath = path.join(extractPath, dbfPath);
    const sourceCRS = await detectCRS(extractPath, prjPath);

    const source = await shapefile.open(shpFullPath, dbfFullPath);
    let featureCount = 0;
    let record;

    const targetCRS = 'EPSG:4326';
    const client = await pool.connect();

    try {
      await client.query('CREATE EXTENSION IF NOT EXISTS postgis');
      await client.query(`
        CREATE TABLE IF NOT EXISTS "${datasetType}" (
          id SERIAL PRIMARY KEY,
          geom GEOMETRY(Geometry, 4326)
        )
      `);

      while ((record = await source.read()) && !record.done) {
        let geojson = record.value;
        if (!geojson.geometry || !geojson.geometry.coordinates || !Array.isArray(geojson.geometry.coordinates)) {
          console.warn(`Skipping invalid geometry for feature ${featureCount + 1}:`, JSON.stringify(geojson).slice(0, 100));
          continue;
        }

        try {
          const coordinates = proj4(sourceCRS, targetCRS, geojson.geometry.coordinates);
          await client.query(
            `INSERT INTO "${datasetType}" (geom) VALUES (ST_GeomFromGeoJSON($1))`,
            [JSON.stringify({ type: geojson.geometry.type, coordinates })]
          );
          featureCount++;
        } catch (projErr) {
          console.error(`Projection error for feature ${featureCount + 1}:`, projErr.stack);
        }
      }

      if (featureCount === 0) {
        throw new Error('No valid features processed');
      }
      return featureCount;
    } finally {
      client.release();
      await fs.rm(extractPath, { recursive: true, force: true }).catch(err => console.warn('Cleanup failed:', err.stack));
    }
  } catch (err) {
    console.error('Upload error:', err.stack);
    throw err;
  }
};

router.post('/:datasetType', authenticateToken, upload.single('file'), async (req, res) => {
  const { datasetType } = req.params;

  if (!VALID_DATASETS.includes(datasetType)) {
    return res.status(400).json({ error: `Invalid dataset type: ${datasetType}` });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const featureCount = await processShapefile(req.file.path, datasetType);
    await fs.unlink(req.file.path);
    res.json({ success: true, message: `Successfully processed ${featureCount} features`, dataset: datasetType });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process shapefile', details: err.message });
  }
});

module.exports = router;