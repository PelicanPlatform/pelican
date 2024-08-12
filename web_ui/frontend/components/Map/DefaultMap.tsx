import React, { ComponentProps } from 'react';
import Map from 'react-map-gl/maplibre';

import 'maplibre-gl/dist/maplibre-gl.css';

export const DefaultMap = ({ ...props }: ComponentProps<typeof Map>) => {
  return (
    <Map
      style={{ width: '100%', height: '100%', ...props.style }}
      mapStyle={{
        version: 8,
        sources: {
          'raster-tiles': {
            type: 'raster',
            tiles: ['https://tile.openstreetmap.org/{z}/{x}/{y}.png'],
            tileSize: 256,
            attribution:
              '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
          },
        },
        layers: [
          {
            id: 'simple-tiles',
            type: 'raster',
            source: 'raster-tiles',
            minzoom: 0,
            maxzoom: 22,
          },
        ],
      }}
      {...props}
    >
      {props.children}
    </Map>
  );
};
