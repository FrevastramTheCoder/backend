const proj4 = require('proj4');
const fs = require('fs');
const shp = require('shpjs');

async function processShapefile(fileBuffer, sourceCRS = 'EPSG:32737') {
  try {
    const geojson = await shp.parseZip(fileBuffer);
    const validFeatures = [];

    for (const feature of geojson.features) {
      if (!feature.geometry || !feature.geometry.coordinates) {
        console.error('Skipping feature: Missing geometry or coordinates');
        continue;
      }

      const processCoordinates = (coords) => {
        if (!Array.isArray(coords) || coords.length === 0) return null;
        return coords.map(coord => {
          if (!Array.isArray(coord) || coord.length < 2) return null;
          const [x, y] = coord;
          if (!isFinite(x) || !isFinite(y)) {
            console.error(`Skipping coordinate [${x}, ${y}]: Non-finite values detected`);
            return null;
          }
          return [x, y];
        }).filter(c => c !== null);
      };

      let transformedCoords;
      try {
        transformedCoords = processCoordinates(feature.geometry.coordinates);
        if (!transformedCoords || transformedCoords.length === 0) {
          console.error(`No valid coordinates after processing for feature ${feature.id || 'unknown'}`);
          continue;
        }

        transformedCoords = proj4(proj4.defs(sourceCRS), proj4.defs('EPSG:4326'), transformedCoords.flat());
        feature.geometry.coordinates = transformedCoords.length > 1 ? [transformedCoords] : transformedCoords;
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