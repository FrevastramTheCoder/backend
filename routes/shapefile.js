
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const shapefile = require('shapefile');
const AdmZip = require('adm-zip');
const { Pool } = require('pg');
const { promisify } = require('util');

const router = express.Router();
const unlink = promisify(fs.unlink);
const rmdir = promisify(fs.rm || fs.rmdir); // Node 14+ uses fs.rm
const pool = new Pool();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', 'uploads', 'shapefiles');
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

// Recursively get all files from a directory
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

// Process shapefile and insert into database
async function processShapefile(datasetType, shpPath, dbfPath) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const source = await shapefile.open(shpPath, dbfPath);
    let result = await source.read();
    if (result.done) throw new Error('Shapefile contains no features');

    const firstFeature = result.value;
    const propKeys = Object.keys(firstFeature.properties || {});
    const columnDefinitions = propKeys.map(k => `"${k}" TEXT`).join(', ');

    await client.query(`
      CREATE TABLE IF NOT EXISTS "${datasetType}" (
        id SERIAL PRIMARY KEY,
        ${columnDefinitions},
        geom GEOMETRY(GEOMETRY, 4326)
      )
    `);

    const insertQuery = `
      INSERT INTO "${datasetType}" (${propKeys.map(k => `"${k}"`).join(', ')}, geom)
      VALUES (${propKeys.map((_, i) => `$${i + 1}`).join(', ')}, ST_GeomFromGeoJSON($${propKeys.length + 1}))
    `;

    let featuresProcessed = 0;
    let batch = [];

    do {
      const feature = result.value;
      if (!feature || !feature.geometry) continue;

      const values = [
        ...propKeys.map(k => feature.properties[k] ?? null),
        JSON.stringify(feature.geometry)
      ];
      batch.push(values.flat());
      featuresProcessed++;

      if (batch.length >= 100) {
        for (const vals of batch) {
          await client.query(insertQuery, vals);
        }
        batch = [];
      }

      result = await source.read();
    } while (!result.done);

    if (batch.length > 0) {
      for (const vals of batch) {
        await client.query(insertQuery, vals);
      }
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

// Upload route
router.post('/:datasetType', upload.single('file'), async (req, res) => {
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
      throw new Error('Shapefile (.shp), .shx, or DBF (.dbf) files missing in ZIP');
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

    // Cleanup
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
