import React from 'react';
import { FmdGood } from '@mui/icons-material';
import { Marker } from 'react-map-gl/maplibre';

import { DefaultMap } from './';

export interface SinglePointMapProps {
  point: { lng: number; lat: number };
  zoom?: number;
}

export const SinglePointMap = ({ point, zoom }: SinglePointMapProps) => {
  return (
    <DefaultMap
      initialViewState={{
        longitude: point.lng,
        latitude: point.lat,
        zoom: zoom || 1,
      }}
      scrollZoom={false}
      style={{ width: '100%', height: '100%' }}
    >
      <Marker longitude={point.lng} latitude={point.lat} anchor='bottom'>
        <FmdGood />
      </Marker>
    </DefaultMap>
  );
};
