const express = require('express');
const router = express.Router();
const pool = require('../middleware/db'); // Updated import
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs').promises;
const { transform } = require('proj4');

const EPSG21037 = '+proj=utm +zone=37 +south +ellps=clrk80 +units=m +no_defs';
const EPSG4326 = '+proj=longlat +datum=WGS84 +no_defs';

router.post('/upload/:dataset', upload.single('file'), async (req, res) => {
  const { dataset } = req.params;
  console.log(`DEBUG: Processing GeoJSON upload for dataset ${dataset}`);

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS buildings (
        id SERIAL PRIMARY KEY,
        geom GEOMETRY(MULTIPOLYGON, 4326) NOT NULL,
        fid FLOAT,
        building_id FLOAT,
        name TEXT,
        floor TEXT,
        size FLOAT,
        offices TEXT,
        use TEXT,
        conditions TEXT
      )
    `);
    console.log('DEBUG: Ensured buildings table schema');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const feature of features) {
        if (feature.geometry?.type !== 'MultiPolygon') {
          console.log(`DEBUG: Skipping feature fid=${feature.properties.fid}: Invalid geometry type ${feature.geometry?.type}`);
          continue;
        }

        const { fid, id: building_id, Name, Floor, size, Offices, use, conditions } = feature.properties;
        const geom = JSON.stringify(feature.geometry);

        await client.query(`
          INSERT INTO buildings (geom, fid, building_id, name, floor, size, offices, use, conditions)
          VALUES (ST_SetSRID(ST_GeomFromGeoJSON($1), 4326), $2, $3, $4, $5, $6, $7, $8, $9)
        `, [geom, fid, building_id, Name, Floor, size, Offices, use, conditions]);
        console.log(`DEBUG: Inserted feature fid=${fid}`);
      }
      await client.query('COMMIT');
      console.log('DEBUG: Transaction committed');
      res.json({ message: `Successfully uploaded ${features.length} features to ${dataset}` });
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