const express = require('express');
const proj4 = require('proj4');
const shp = require('shpjs');
const multer = require('multer');
const pool = require('../middleware/db'); // Corrected import for db.js in middleware folder

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Define VALID_DATASETS to match server.js
const VALID_DATASETS = [
  'buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads',
  'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection',
  'parking', 'vegetation', 'aruboundary'
];

// Define EPSG:21037 (Arc 1960/UTM zone 37S)
proj4.defs('EPSG:21037', '+proj=utm +zone=37 +south +ellps=clrk80 +towgs84=-160,-6,-302,0,0,0,0 +units=m +no_defs');

async function processShapefile(fileBuffer, sourceCRS = 'EPSG:21037') {
  try {
    const geojson = await shp.parseZip(fileBuffer);
    const validFeatures = [];
    const invalidFeatures = [];

    const processCoordinates = (coords, depth = 0) => {
      if (!Array.isArray(coords) || coords.length === 0) {
        console.error(`Empty or invalid coordinate array at depth ${depth}`);
        return null;
      }

      console.log(`Processing coordinates at depth ${depth}:`, JSON.stringify(coords).slice(0, 100) + '...');

      // Handle flat coordinate arrays (e.g., [x1, y1, x2, y2, ...])
      if (depth === 0 && coords.every(c => typeof c === 'number')) {
        const pairedCoords = [];
        for (let i = 0; i < coords.length; i += 2) {
          const x = coords[i];
          const y = coords[i + 1];
          if (!isFinite(x) || !isFinite(y)) {
            console.error(`Non-finite coordinate [${x}, ${y}] at depth ${depth}`);
            continue;
          }
          pairedCoords.push([x, y]);
        }
        return pairedCoords.length > 0 ? pairedCoords : null;
      }

      // Handle nested coordinate arrays
      const processed = coords.map(coord => {
        if (Array.isArray(coord)) {
          return processCoordinates(coord, depth + 1);
        }
        if (!Array.isArray(coord) || coord.length !== 2 || !coord.every(c => typeof c === 'number')) {
          console.error(`Invalid coordinate structure at depth ${depth}:`, coord);
          return null;
        }
        const [x, y] = coord;
        if (!isFinite(x) || !isFinite(y)) {
          console.error(`Non-finite coordinate [${x}, ${y}] at depth ${depth}`);
          return null;
        }
        return [x, y];
      }).filter(c => c !== null);

      return processed.length > 0 ? processed : null;
    };

    for (const feature of geojson.features) {
      if (!feature.geometry || !feature.geometry.coordinates || !feature.geometry.type) {
        invalidFeatures.push({ id: feature.id || 'unknown', reason: 'Missing geometry, coordinates, or type' });
        continue;
      }

      let transformedCoords;
      try {
        transformedCoords = processCoordinates(feature.geometry.coordinates);
        if (!transformedCoords || transformedCoords.length === 0) {
          invalidFeatures.push({ id: feature.id || 'unknown', reason: 'No valid coordinates after processing' });
          continue;
        }

        const transformNested = (coords, geometryType) => {
          if (geometryType === 'MultiPolygon') {
            return coords.map(polygon => polygon.map(ring => ring.map(pair => {
              const result = proj4(sourceCRS, 'EPSG:4326', pair);
              return result && result.length === 2 && isFinite(result[0]) && isFinite(result[1]) ? result : null;
            }).filter(p => p !== null)).filter(r => r.length > 0));
          }
          if (geometryType === 'Polygon') {
            return coords.map(ring => ring.map(pair => {
              const result = proj4(sourceCRS, 'EPSG:4326', pair);
              return result && result.length === 2 && isFinite(result[0]) && isFinite(result[1]) ? result : null;
            }).filter(p => p !== null)).filter(r => r.length > 0);
          }
          return coords.map(pair => {
            const result = proj4(sourceCRS, 'EPSG:4326', pair);
            return result && result.length === 2 && isFinite(result[0]) && isFinite(result[1]) ? result : null;
          }).filter(p => p !== null);
        };

        transformedCoords = transformNested(transformedCoords, feature.geometry.type);
        console.log(`Transformed ${transformedCoords.length} coordinate sets for feature ${feature.id || 'unknown'}`);

        if (!transformedCoords || transformedCoords.length === 0) {
          invalidFeatures.push({ id: feature.id || 'unknown', reason: 'No valid transformed coordinates' });
          continue;
        }

        // Update geometry coordinates based on type
        if (feature.geometry.type === 'Polygon') {
          feature.geometry.coordinates = transformedCoords.length > 0 ? [transformedCoords[0]] : [];
        } else if (feature.geometry.type === 'MultiPolygon') {
          feature.geometry.coordinates = transformedCoords.map(coords => [coords]);
        } else if (feature.geometry.type === 'Point' || feature.geometry.type === 'MultiPoint' || feature.geometry.type === 'LineString' || feature.geometry.type === 'MultiLineString') {
          feature.geometry.coordinates = transformedCoords;
        } else {
          invalidFeatures.push({ id: feature.id || 'unknown', reason: `Unsupported geometry type: ${feature.geometry.type}` });
          continue;
        }

        // Validate geometry
        if (!feature.geometry.coordinates || feature.geometry.coordinates.length === 0) {
          invalidFeatures.push({ id: feature.id || 'unknown', reason: 'Empty coordinates after transformation' });
          continue;
        }

        validFeatures.push(feature);
      } catch (projError) {
        console.error(`Projection error for feature ${feature.id || 'unknown'}:`, projError.stack);
        invalidFeatures.push({ id: feature.id || 'unknown', reason: `Projection error: ${projError.message}` });
        continue;
      }
    }

    if (validFeatures.length === 0) {
      console.error('No valid features processed:', JSON.stringify(invalidFeatures, null, 2));
      throw new Error(`No valid features processed. Invalid features: ${JSON.stringify(invalidFeatures)}`);
    }

    return validFeatures;
  } catch (error) {
    console.error(`Shapefile processing error: ${error.message}`);
    throw error;
  }
}

router.post('/:datasetType', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const datasetType = req.params.datasetType;
    if (!VALID_DATASETS.includes(datasetType)) {
      return res.status(400).json({ error: `Invalid dataset: ${datasetType}` });
    }

    const features = await processShapefile(req.file.buffer, 'EPSG:21037');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const feature of features) {
        const properties = feature.properties || {};
        // Define allowed columns based on dataset schema (from server.js)
        const allowedColumns = {
          buildings: ['name', 'description', 'floor', 'size', 'offices', 'use', 'condition'],
          roads: ['name', 'description', 'size', 'condition', 'function'],
          drainageSystems: ['name', 'description', 'type', 'condition'],
          footpaths: ['name', 'description'],
          electricitySupply: ['name', 'description'],
          securityLights: ['name', 'description'],
          recreationalAreas: ['name', 'description'],
          vimbweta: ['name', 'description'],
          solidWasteCollection: ['name', 'description'],
          parking: ['name', 'description'],
          vegetation: ['name', 'description'],
          aruboundary: ['name', 'description']
        }[datasetType] || ['name', 'description'];

        // Filter properties to only include allowed columns
        const filteredProperties = {};
        for (const key of allowedColumns) {
          if (properties[key] !== undefined) {
            filteredProperties[key] = properties[key];
          }
        }

        const columns = ['geom', ...Object.keys(filteredProperties)];
        const values = [JSON.stringify(feature.geometry), ...Object.values(filteredProperties)];
        const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
        const columnNames = columns.map(c => `"${c}"`).join(', ');

        await client.query(
          `INSERT INTO "${datasetType}" (${columnNames}) VALUES (${placeholders}) RETURNING id`,
          values
        );
      }
      await client.query('COMMIT');
      res.json({ message: `Shapefile processed and ${features.length} features inserted into ${datasetType}`, features });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error(`Database insertion error for ${datasetType}:`, err.stack);
      throw new Error(`Failed to insert features into ${datasetType}: ${err.message}`);
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(`Shapefile upload error for ${req.params.datasetType}:`, error.message);
    next(error);
  }
});

module.exports = router;