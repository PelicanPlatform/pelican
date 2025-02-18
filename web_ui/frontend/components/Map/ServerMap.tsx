import React, { useContext, useMemo, useState } from 'react';
import {
  AttributionControl,
  LngLat,
  LngLatLike,
  Marker,
  Popup,
} from 'react-map-gl/maplibre';
import { TripOrigin, Storage } from '@mui/icons-material';

import { DefaultMap, PopOutCard, ServerCard } from '@/components/Map';
import { Server } from '@/index';

import 'maplibre-gl/dist/maplibre-gl.css';
import { alertOnError } from '@/helpers/util';
import { getDirectorServer } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { ServerDetailed, ServerGeneral } from '@/types';
import { Box } from '@mui/material';

interface ServerMapProps {
  servers?: ServerGeneral[];
}

export const ServerMap = ({ servers }: ServerMapProps) => {
  const dispatch = useContext(AlertDispatchContext);

  const [activeServer, setActiveServer] = useState<
    ServerGeneral | ServerDetailed | undefined
  >(undefined);

  const _setActiveServer = (server: ServerGeneral | undefined) => {
    setActiveServer(server);

    if (server?.type == 'Origin') {
      alertOnError(
        async () => {
          const response = await getDirectorServer(server.name);
          setActiveServer(await response.json());
        },
        'Failed to fetch server details',
        dispatch
      );
    }
  };

  const serverMarkers = useMemo(() => {
    return servers?.map((server) => {
      return (
        <ServerMarker
          server={server}
          onClick={(x) => {
            _setActiveServer(x);
          }}
          key={server.name}
        />
      );
    });
  }, [servers]);

  return (
    <>
      <Box position={'relative'} flexGrow={1}>
        <PopOutCard
          title={activeServer?.name}
          active={activeServer != undefined}
          onClose={() => _setActiveServer(undefined)}
        >
          <ServerCard server={activeServer} />
        </PopOutCard>
        <DefaultMap style={{ width: '100%', height: '100%' }}>
          {serverMarkers}
        </DefaultMap>
      </Box>
    </>
  );
};

const ServerMarker = ({
  server,
  onClick,
}: {
  server: ServerGeneral;
  onClick: (server: ServerGeneral) => void;
}) => {
  return (
    <>
      <Marker
        offset={[0, -10]}
        longitude={jitter(server.longitude)}
        latitude={jitter(server.latitude)}
        key={server.name}
        onClick={() => {
          onClick(server);
        }}
        style={{ cursor: 'pointer' }}
      >
        {server.type == 'Origin' ? <TripOrigin /> : <Storage />}
      </Marker>
    </>
  );
};

/**
 * Jitter the coordinates of a server to prevent markers from overlapping
 * @param n The latitude or longitude to jitter
 * @param distance The ~ # of meters to jitter the coordinates by
 */
const jitter = (n: number, distance: number = 1000) => {
  return n + (Math.random() - 0.5) * (0.000009 * distance);
};
