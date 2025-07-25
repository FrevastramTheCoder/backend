const express = require('express');
const router = express.Router();
const pool = require('../middleware/db');
const { authenticateToken } = require('../middleware/authMiddleware');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs').promises;
const pgFormat = require('pg-format');
const { transform } = require('proj4');

const EPSG21037 = '+proj=utm +zone=37 +south +ellps=clrk80 +units=m +no_defs';
const EPSG4326 = '+proj=longlat +datum=WGS84 +no_defs';

const VALID_DATASETS = [
  'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
  'drainageStructures', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
  'parking', 'vegetation', 'aruboundary'
];

router.post('/upload/:dataset', authenticateToken, upload.single('file'), async (req, res) => {
  const { dataset } = req.params;
  console.log(`DEBUG: Processing GeoJSON upload for dataset ${dataset}`);

  if (!VALID_DATASETS.includes(dataset)) {
    console.log(`ERROR: Invalid dataset: ${dataset}`);
    return res.status(400).json({ error: { message: `Invalid dataset: ${dataset}` } });
  }

  if (!req.file) {
    console.log('ERROR: No file uploaded');
    return res.status(400).json({ error: { message: 'No file uploaded' } });
  }

  try {
    console.log(`DEBUG: Parsing file ${req.file.originalname}`);
    const geojsonData = JSON.parse(await fs.readFile(req.file.path, 'utf-8'));

    if (geojsonData.type !== 'FeatureCollection' || !Array.isArray(geojsonData.features)) {
      console.log('ERROR: Invalid GeoJSON format');
      return res.status(400).json({ error: { message: 'Invalid GeoJSON format' } });
    }

    let features = geojsonData.features;
    if (geojsonData.crs?.properties?.name === 'urn:ogc:def:crs:EPSG::21037') {
      console.log('DEBUG: Reprojecting from EPSG:21037 to EPSG:4326');
      features = geojsonData.features.map(feature => {
        if (feature.geometry?.type === 'MultiPolygon') {
          return {
            ...feature,
            geometry: {
              ...feature.geometry,
              coordinates: feature.geometry.coordinates.map(polygon =>
                polygon.map(ring =>
                  ring.map(([x, y]) => {
                    const [lon, lat] = transform(EPSG21037, EPSG4326, [x, y]);
                    return [lon, lat];
                  })
                )
              )
            }
          };
        }
        return feature;
      });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const validFeatures = features.filter(feature => feature.geometry?.type === 'MultiPolygon');
      if (validFeatures.length === 0) {
        console.log('ERROR: No valid MultiPolygon features found');
        await client.query('ROLLBACK');
        return res.status(400).json({ error: { message: 'No valid MultiPolygon features found' } });
      }

      const values = validFeatures.map(feature => {
        const { fid, id: building_id, Name, Floor, size, Offices, use, conditions } = {
          fid: null,
          id: null,
          Name: null,
          Floor: null,
          size: null,
          Offices: null,
          use: null,
          conditions: null,
          ...feature.properties
        };
        return [JSON.stringify(feature.geometry), fid, building_id, Name, Floor, size, Offices, use, conditions];
      });

      const query = pgFormat(`
        INSERT INTO "${dataset}" (geom, fid, building_id, name, floor, size, offices, use, conditions)
        VALUES %L
      `, values.map(v => [pgFormat.literal(v[0]), ...v.slice(1)]));
      await client.query(query);
      console.log(`DEBUG: Inserted ${values.length} features`);
      await client.query('COMMIT');
      res.json({ message: `Successfully uploaded ${values.length} features to ${dataset}` });
    } catch (dbError) {
      await client.query('ROLLBACK');
      console.error('ERROR: Database error:', dbError.message, dbError.stack);
      res.status(500).json({ error: { message: 'Database error', details: dbError.message } });
    } finally {
      client.release();
    }

    await fs.unlink(req.file.path);
  } catch (error) {
    console.error('ERROR: Processing error:', error.message, error.stack);
    res.status(500).json({ error: { message: 'Failed to process GeoJSON', details: error.message } });
  }
});

module.exports = router;