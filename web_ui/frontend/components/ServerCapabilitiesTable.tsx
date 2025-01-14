/**
 * Table to display the server capabilities with its namespaces
 */

import { ServerDetailed, ServerGeneral } from '@/types';
import { Box, Grid, Typography } from '@mui/material';
import { CapabilitiesRow } from '@/app/director/components/DirectorDropdown';
import { grey } from '@mui/material/colors';

interface ServerCapabilitiesTableProps {
  server: ServerGeneral | ServerDetailed;
}

/**
 * Create a grid table that displays the server capabilities with the namespaces
 * listed below indicating their individual capabilities and how they interact
 * with the servers own capabilities.
 * @param server
 * @constructor
 */
export const ServerCapabilitiesTable = ({
  server,
}: ServerCapabilitiesTableProps) => {
  return (
    <Grid container spacing={1}>
      <Grid item xs={12}>
        <Box
          bgcolor={grey[300]}
          display={'flex'}
          p={1}
          py={0.5}
          borderRadius={1}
        >
          <Grid container spacing={1}>
            <Grid item xs={12} md={3}>
              <Box display={'flex'} height={'100%'}>
                <Typography variant={'body2'} my={'auto'}>
                  {server.type}&apos;s Namespace Capabilities
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={9}>
              <CapabilitiesRow capabilities={server.capabilities} />
            </Grid>
          </Grid>
        </Box>
      </Grid>
      {'namespaces' in server &&
        server?.namespaces
          ?.sort((a, b) => a.path.localeCompare(b.path))
          ?.map((namespace) => (
            <Grid key={namespace.path} item xs={12}>
              <Box display={'flex'} px={1} borderRadius={1}>
                <Grid container spacing={1}>
                  <Grid item xs={12} md={3}>
                    <Box display={'flex'} height={'100%'}>
                      <Typography variant={'body2'} my={'auto'}>
                        {namespace.path}
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={9}>
                    <CapabilitiesRow
                      capabilities={namespace.capabilities}
                      parentCapabilities={server.capabilities}
                    />
                  </Grid>
                </Grid>
              </Box>
            </Grid>
          ))}
    </Grid>
  );
};
