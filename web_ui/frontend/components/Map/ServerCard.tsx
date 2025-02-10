import { Box, Grid, Typography } from '@mui/material';
import { InformationSpan } from '@/components';
import { ServerCapabilitiesTable } from '@/components/ServerCapabilitiesTable';
import React from 'react';
import { ServerDetailed, ServerGeneral } from '@/types';

const ServerCard = ({
  server,
}: {
  server?: ServerGeneral | ServerDetailed;
}) => {
  // If there is no server, return null
  if (!server) {
    return null;
  }

  return (
    <Box>
      <Grid container spacing={1}>
        <Grid item xs={12}>
          <InformationSpan name={'Type'} value={server.type} />
          <InformationSpan name={'Status'} value={server.healthStatus} />
          <InformationSpan name={'URL'} value={server.url} />
          <InformationSpan
            name={'Longitude'}
            value={server.longitude.toString()}
          />
          <InformationSpan
            name={'Latitude'}
            value={server.latitude.toString()}
          />
        </Grid>
      </Grid>
      {server.type == 'Origin' && (
        <Box sx={{ my: 1 }}>
          <ServerCapabilitiesTable server={server} />
        </Box>
      )}
    </Box>
  );
};

export default ServerCard;
