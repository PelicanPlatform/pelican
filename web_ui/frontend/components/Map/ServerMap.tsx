import React, { useState } from 'react';
import {
  AttributionControl,
  LngLatLike,
  Marker,
  Popup,
} from 'react-map-gl/maplibre';
import { FmdGood } from '@mui/icons-material';

import { DefaultMap } from './';
import { Server } from '@/index';

import 'maplibre-gl/dist/maplibre-gl.css';
import { Box, Typography } from '@mui/material';

interface ServerMapProps {
  servers?: Server[];
}

export const ServerMap = ({ servers }: ServerMapProps) => {
  return (
    <DefaultMap style={{ width: '100%', height: '100%' }}>
      {servers &&
        servers.map((server) => {
          return <ServerMarker server={server} key={server.name} />;
        })}
    </DefaultMap>
  );
};

const ServerMarker = ({ server }: { server: Server }) => {
  const [showPopup, setShowPopup] = useState(false);

  return (
    <>
      <Marker
        offset={[0, -10]}
        longitude={server.longitude}
        latitude={server.latitude}
        key={server.name}
        onClick={() => {
          setShowPopup(true);
        }}
        style={{ cursor: 'pointer' }}
      >
        <FmdGood />
      </Marker>
      {showPopup && (
        <Popup
          longitude={server.longitude}
          latitude={server.latitude}
          closeOnClick={false}
          onClose={() => setShowPopup(false)}
          offset={[0, -24] as [number, number]}
        >
          <Box>
            <Typography variant={'body1'}>{server.name} TEst</Typography>
          </Box>
        </Popup>
      )}
    </>
  );
};
