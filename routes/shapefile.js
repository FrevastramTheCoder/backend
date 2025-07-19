// ===============================
// routes/shapefileUpload.js
// ===============================

const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const unzipper = require('unzipper');
const shapefile = require('shapefile');
const router = express.Router();

const upload = multer({ dest: 'uploads/' });

// Extract geometry types from shapefile
router.post('/api/extract-geometry-type', upload.single('shapefile'), async (req, res) => {
  try {
    const zipFilePath = req.file.path;
    const extractPath = path.join(__dirname, '../uploads/', `shapefile_${Date.now()}`);
    fs.mkdirSync(extractPath, { recursive: true });

    await fs.createReadStream(zipFilePath)
      .pipe(unzipper.Extract({ path: extractPath }))
      .promise();

    const files = fs.readdirSync(extractPath);
    const shpFile = files.find(f => f.endsWith('.shp'));
    const dbfFile = files.find(f => f.endsWith('.dbf'));

    if (!shpFile || !dbfFile) {
      return res.status(400).json({ error: 'Missing .shp or .dbf file in the zip.' });
    }

    const shpPath = path.join(extractPath, shpFile);
    const dbfPath = path.join(extractPath, dbfFile);

    const source = await shapefile.open(shpPath, dbfPath);
    const geometryTypes = new Set();

    while (true) {
      const result = await source.read();
      if (result.done) break;
      if (result.value && result.value.geometry && result.value.geometry.type) {
        geometryTypes.add(result.value.geometry.type);
      }
    }

    if (geometryTypes.size === 0) {
      return res.status(400).json({ error: 'No valid geometry types returned from server. Ensure the shapefile contains valid features with supported geometry types (e.g., Polygon, LineString, Point).' });
    }

    return res.json({ geometryTypes: Array.from(geometryTypes) });
  } catch (error) {
    console.error('Error extracting geometry types:', error);
    return res.status(500).json({ error: 'Failed to extract geometry types.' });
  } finally {
    // Optional: Clean up uploaded files
    fs.rmSync(req.file.path, { force: true });
  }
});

module.exports = router;
