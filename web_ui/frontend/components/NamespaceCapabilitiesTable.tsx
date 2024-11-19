/**
 * A table to display the capabilities of a namespace
 */

/**
 * Table to display the server capabilities with its namespaces
 */

import { DirectorNamespace, ServerDetailed, ServerGeneral } from '@/types';
import { Box, Grid, Typography, useTheme } from '@mui/material';
import { CapabilitiesRow } from '@/app/director/components/DirectorDropdown';
import { grey } from '@mui/material/colors';
import { NamespaceIcon } from '@/components/Namespace';

interface NamespaceCapabilitiesTableProps {
  namespace: DirectorNamespace;
  servers?: ServerDetailed[];
}

/**
 * Create a grid table that displays the server capabilities with the namespaces
 * listed below indicating their individual capabilities and how they interact
 * with the servers own capabilities.
 * @param server
 * @constructor
 */
export const NamespaceCapabilitiesTable = ({
  namespace,
  servers,
}: NamespaceCapabilitiesTableProps) => {
  const theme = useTheme();

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
            <Grid item xs={3}>
              <Box display={'flex'} height={'100%'}>
                <Typography variant={'body2'} my={'auto'}>
                  Namespace Capabilities
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={9}>
              <CapabilitiesRow capabilities={namespace.capabilities} />
            </Grid>
          </Grid>
        </Box>
      </Grid>
      {servers &&
        servers
          ?.sort((a, b) => a.name.localeCompare(b.name))
          ?.map((server) => (
            <Grid key={server.name} item xs={12}>
              <Box display={'flex'} px={1} borderRadius={1}>
                <Grid container spacing={1}>
                  <Grid item xs={3}>
                    <Box display={'flex'} height={'100%'}>
                      <Typography
                        variant={'body2'}
                        my={'auto'}
                        display={'flex'}
                      >
                        <NamespaceIcon
                          serverType={
                            server.type.toLowerCase() as 'origin' | 'cache'
                          }
                          size={'small'}
                          bgcolor={'white'}
                          color={theme.palette.primary.main}
                        />
                        {server.name}
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={9}>
                    <CapabilitiesRow
                      capabilities={server.capabilities}
                      parentCapabilities={namespace.capabilities}
                    />
                  </Grid>
                </Grid>
              </Box>
            </Grid>
          ))}
    </Grid>
  );
};
