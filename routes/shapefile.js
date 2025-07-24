const express = require('express');
const multer = require('multer');
const shp = require('shpjs');
const proj4 = require('proj4');
const pool = require('../middleware/db');
const { authenticateToken } = require('../middleware/authMiddleware');

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.originalname.toLowerCase().endsWith('.zip')) {
      cb(null, true);
    } else {
      cb(new Error('Only .zip shapefile archives are allowed for GeoJSON conversion'));
    }
  }
});

// Valid datasets to match server.js and Datasets.jsx
const VALID_DATASETS = [
  'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
  'drainageStructures', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
  'parking', 'vegetation', 'aruboundary'
];

// Valid GeoJSON geometry types
const VALID_GEOMETRY_TYPES = ['Point', 'MultiPoint', 'LineString', 'MultiLineString', 'Polygon', 'MultiPolygon'];

// Define EPSG:21037 (Arc 1960/UTM zone 37S)
proj4.defs('EPSG:21037', '+proj=utm +zone=37 +south +ellps=clrk80 +towgs84=-160,-6,-302,0,0,0,0 +units=m +no_defs');

async function validateGeoJSONFeature(feature) {
  if (!feature || feature.type !== 'Feature') {
    return { valid: false, reason: 'Not a valid GeoJSON Feature' };
  }
  if (!feature.geometry || !feature.geometry.type || !VALID_GEOMETRY_TYPES.includes(feature.geometry.type)) {
    return { valid: false, reason: `Invalid or unsupported geometry type: ${feature.geometry?.type || 'undefined'}` };
  }
  if (!feature.geometry.coordinates || !Array.isArray(feature.geometry.coordinates)) {
    return { valid: false, reason: 'Missing or invalid coordinates' };
  }

  function isValidCoord(c) {
    return Array.isArray(c) && c.length >= 2 && c.every(n => isFinite(n));
  }

  const coords = feature.geometry.coordinates;
  const type = feature.geometry.type;
  let valid = false;

  if (type === 'Point') {
    valid = isValidCoord(coords);
  } else if (type === 'MultiPoint' || type === 'LineString') {
    valid = Array.isArray(coords) && coords.every(isValidCoord);
  } else if (type === 'Polygon') {
    valid = Array.isArray(coords) && coords.every(ring => Array.isArray(ring) && ring.every(isValidCoord));
  } else if (type === 'MultiLineString') {
    valid = Array.isArray(coords) && coords.every(line => Array.isArray(line) && line.every(isValidCoord));
  } else if (type === 'MultiPolygon') {
    valid = Array.isArray(coords) && coords.every(poly => Array.isArray(poly) && poly.every(ring => Array.isArray(ring) && ring.every(isValidCoord)));
  }

  if (!valid) {
    return { valid: false, reason: 'Invalid coordinate structure for geometry type' };
  }
  return { valid: true };
}

async function processShapefile(fileBuffer, sourceCRS = 'EPSG:21037') {
  try {
    const geojson = await shp.parseZip(fileBuffer);
    if (!geojson.features || !Array.isArray(geojson.features) || geojson.features.length === 0) {
      throw new Error('No valid features found in shapefile. Ensure the .zip contains valid .shp, .shx, and .dbf files.');
    }

    const validFeatures = [];
    const invalidFeatures = [];

    for (const feature of geojson.features) {
      const validation = await validateGeoJSONFeature(feature);
      if (!validation.valid) {
        invalidFeatures.push({ id: feature.id || 'unknown', reason: validation.reason });
        continue;
      }

      const transformCoordinates = (coords, geometryType) => {
        if (!Array.isArray(coords)) return null;

        if (geometryType === 'Point') {
          const [x, y] = coords;
          if (!isFinite(x) || !isFinite(y)) return null;
          return proj4(sourceCRS, 'EPSG:4326', [x, y]);
        } else if (geometryType === 'LineString' || geometryType === 'MultiPoint') {
          return coords.map(point => {
            if (!Array.isArray(point) || point.length < 2) return null;
            const [x, y] = point;
            if (!isFinite(x) || !isFinite(y)) return null;
            return proj4(sourceCRS, 'EPSG:4326', [x, y]);
          }).filter(c => c !== null);
        } else if (geometryType === 'Polygon') {
          return coords.map(ring => ring.map(point => {
            if (!Array.isArray(point) || point.length < 2) return null;
            const [x, y] = point;
            if (!isFinite(x) || !isFinite(y)) return null;
            return proj4(sourceCRS, 'EPSG:4326', [x, y]);
          }).filter(c => c !== null)).filter(r => r.length > 0);
        } else if (geometryType === 'MultiPolygon') {
          return coords.map(polygon => polygon.map(ring => ring.map(point => {
            if (!Array.isArray(point) || point.length < 2) return null;
            const [x, y] = point;
            if (!isFinite(x) || !isFinite(y)) return null;
            return proj4(sourceCRS, 'EPSG:4326', [x, y]);
          }).filter(c => c !== null)).filter(r => r.length > 0)).filter(p => p.length > 0);
        } else if (geometryType === 'MultiLineString') {
          return coords.map(line => line.map(point => {
            if (!Array.isArray(point) || point.length < 2) return null;
            const [x, y] = point;
            if (!isFinite(x) || !isFinite(y)) return null;
            return proj4(sourceCRS, 'EPSG:4326', [x, y]);
          }).filter(c => c !== null)).filter(l => l.length > 0);
        }
        return null;
      };

      const transformedCoords = transformCoordinates(feature.geometry.coordinates, feature.geometry.type);
      if (!transformedCoords || transformedCoords.length === 0) {
        invalidFeatures.push({ id: feature.id || 'unknown', reason: 'No valid coordinates after transformation to EPSG:4326' });
        continue;
      }

      feature.geometry.coordinates = transformedCoords;
      validFeatures.push(feature);
    }

    if (validFeatures.length === 0) {
      throw new Error(`No valid GeoJSON features produced. Invalid features: ${JSON.stringify(invalidFeatures)}`);
    }

    return validFeatures;
  } catch (error) {
    console.error('Shapefile to GeoJSON conversion error:', error.message);
    throw new Error(`Failed to convert shapefile to GeoJSON: ${error.message}`);
  }
}

// Sanitize column names to be SQL-safe
function sanitizeColumnName(name) {
  // Remove invalid characters, replace spaces with underscores, and ensure it doesn't start with a number
  return name
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/^(\d)/, '_$1')
    .toLowerCase()
    .substring(0, 63); // PostgreSQL column name length limit
}

async function ensureTableSchema(client, datasetType, properties) {
  // Get unique property keys across all features
  const propertyKeys = [...new Set(properties.flatMap(f => Object.keys(f.properties || {})))];
  const sanitizedColumns = propertyKeys.map(key => ({
    original: key,
    sanitized: sanitizeColumnName(key)
  }));

  // Check if table exists
  const tableExists = await client.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables 
      WHERE table_name = $1
    )
  `, [datasetType]);

  if (!tableExists.rows[0].exists) {
    // Create new table
    const columns = [
      'id SERIAL PRIMARY KEY',
      'geom GEOMETRY NOT NULL',
      ...sanitizedColumns.map(col => `"${col.sanitized}" TEXT`)
    ].join(', ');
    await client.query(`
      CREATE TABLE "${datasetType}" (${columns})
    `);
    await client.query(`
      SELECT UpdateGeometrySRID('${datasetType}', 'geom', 4326)
    `);
    console.log(`✅ Created table ${datasetType} with dynamic columns: ${sanitizedColumns.map(c => c.sanitized).join(', ')}`);
  } else {
    // Check existing columns
    const existingColumns = await client.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = $1
    `, [datasetType]);
    const existingColumnNames = existingColumns.rows.map(row => row.column_name);

    // Add missing columns
    for (const col of sanitizedColumns) {
      if (!existingColumnNames.includes(col.sanitized)) {
        await client.query(`
          ALTER TABLE "${datasetType}" ADD COLUMN "${col.sanitized}" TEXT
        `);
        console.log(`✅ Added column ${col.sanitized} to table ${datasetType}`);
      }
    }
  }

  return sanitizedColumns;
}

router.post('/:datasetType', authenticateToken, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No shapefile uploaded. Please upload a .zip archive for GeoJSON conversion.' });
    }

    const { datasetType } = req.params;
    if (!VALID_DATASETS.includes(datasetType)) {
      return res.status(400).json({ error: `Invalid dataset: ${datasetType}` });
    }

    const features = await processShapefile(req.file.buffer, 'EPSG:21037');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Ensure table schema matches feature properties
      const sanitizedColumns = await ensureTableSchema(client, datasetType, features);

      const insertedRecords = [];
      for (const feature of features) {
        const properties = feature.properties || {};
        const filteredProperties = {};
        sanitizedColumns.forEach(col => {
          if (properties[col.original] !== undefined && properties[col.original] !== null) {
            filteredProperties[col.sanitized] = String(properties[col.original]).substring(0, 255);
          }
        });

        const columns = ['geom', ...Object.keys(filteredProperties)];
        const values = [JSON.stringify(feature.geometry), ...Object.values(filteredProperties)];
        const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
        const columnNames = columns.map(c => `"${c}"`).join(', ');

        const result = await client.query(
          `INSERT INTO "${datasetType}" (${columnNames}) VALUES (${placeholders}) RETURNING *`,
          values
        );

        const { id, geom, ...recordProperties } = result.rows[0];
        insertedRecords.push({
          id,
          properties: recordProperties,
          geometry: geom ? JSON.parse(geom) : null
        });
      }

      await client.query('COMMIT');
      res.json({
        message: `Successfully converted shapefile to GeoJSON and uploaded ${insertedRecords.length} features to ${datasetType} with dynamic schema`,
        records: insertedRecords
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Failed to insert GeoJSON features into ${datasetType}: ${err.message}`);
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(`Shapefile upload error for ${req.params.datasetType}:`, err.stack);
    res.status(500).json({
      error: {
        message: err.message || 'Failed to convert shapefile to GeoJSON and upload',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
      }
    });
  }
});

module.exports = router;