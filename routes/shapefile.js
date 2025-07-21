const express = require('express');
const proj4 = require('proj4');
const shp = require('shpjs');
const multer = require('multer'); // Assuming multer is used for file uploads

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() }); // Store file in memory as buffer

async function processShapefile(fileBuffer, sourceCRS = 'EPSG:32737') {
  try {
    const geojson = await shp.parseZip(fileBuffer);
    const validFeatures = [];

    const processCoordinates = (coords, depth = 0) => {
      if (!Array.isArray(coords) || coords.length === 0) return null;
      return coords.map(coord => {
        if (Array.isArray(coord)) {
          return processCoordinates(coord, depth + 1);
        }
        if (!Array.isArray(coord) || coord.length < 2) {
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
    };

    for (const feature of geojson.features) {
      if (!feature.geometry || !feature.geometry.coordinates) {
        console.error(`Skipping feature ${feature.id || 'unknown'}: Missing geometry or coordinates`);
        continue;
      }

      let transformedCoords;
      try {
        transformedCoords = processCoordinates(feature.geometry.coordinates);
        if (!transformedCoords || transformedCoords.length === 0) {
          console.error(`No valid coordinates after processing for feature ${feature.id || 'unknown'}`);
          continue;
        }

        const transformNested = (coords) => {
          if (Array.isArray(coords[0]) && Array.isArray(coords[0][0])) {
            return coords.map(ring => proj4(proj4.defs(sourceCRS), proj4.defs('EPSG:4326'), ring.flat()));
          }
          return proj4(proj4.defs(sourceCRS), proj4.defs('EPSG:4326'), coords.flat());
        };

        transformedCoords = transformNested(transformedCoords);
        console.log(`Transformed ${transformedCoords.length} coordinate sets for feature ${feature.id || 'unknown'}`);

        if (feature.geometry.type === 'Polygon') {
          feature.geometry.coordinates = [transformedCoords];
        } else if (feature.geometry.type === 'MultiPolygon') {
          feature.geometry.coordinates = transformedCoords.map(coords => [coords]);
        } else {
          feature.geometry.coordinates = transformedCoords;
        }
      } catch (projError) {
        console.error(`Projection error for feature ${feature.id || 'unknown'}: ${projError.message}`);
        continue;
      }

      validFeatures.push(feature);
    }

    if (validFeatures.length === 0) {
      throw new Error('No valid features processed. Check shapefile for invalid coordinates.');
    }

    return validFeatures;
  } catch (error) {
    console.error(`Upload error: ${error.message}`);
    throw error;
  }
}

router.post('/:datasetType', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const datasetType = req.params.datasetType;
    const validDatasets = ['buildings', 'footpaths', 'electricitySupply', 'securityLights', 'roads', 'drainageSystems', 'recreationalAreas', 'vimbweta', 'solidWasteCollection', 'parking', 'vegetation', 'aruboundary'];
    if (!validDatasets.includes(datasetType)) {
      return res.status(400).json({ error: `Invalid dataset: ${datasetType}` });
    }

    const features = await processShapefile(req.file.buffer);
    res.json({ message: 'Shapefile processed successfully', features });
  } catch (error) {
    next(error);
  }
});

module.exports = router;