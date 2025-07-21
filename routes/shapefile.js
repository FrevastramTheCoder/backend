const proj4 = require('proj4');
const fs = require('fs');
const shp = require('shpjs');

async function processShapefile(fileBuffer, sourceCRS = 'EPSG:32737') {
  try {
    const geojson = await shp.parseZip(fileBuffer);
    const validFeatures = [];

    const processCoordinates = (coords, depth = 0) => {
      if (!Array.isArray(coords) || coords.length === 0) return null;
      return coords.map(coord => {
        if (Array.isArray(coord)) {
          // Recursively process nested arrays
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

        // Flatten and transform
        const flatCoords = Array.isArray(transformedCoords[0]) ? transformedCoords.flat(Infinity) : transformedCoords;
        console.log(`Transforming ${flatCoords.length} coordinates for feature ${feature.id || 'unknown'}`);
        transformedCoords = proj4(proj4.defs(sourceCRS), proj4.defs('EPSG:4326'), flatCoords);

        // Reconstruct geometry
        if (['Polygon', 'MultiPolygon'].includes(feature.geometry.type)) {
          feature.geometry.coordinates = [transformedCoords]; // Wrap for Polygon/MultiPolygon
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
      throw new Error('No valid features processed');
    }

    return validFeatures;
  } catch (error) {
    console.error(`Upload error: ${error.message}`);
    throw error;
  }
}

module.exports = { processShapefile };