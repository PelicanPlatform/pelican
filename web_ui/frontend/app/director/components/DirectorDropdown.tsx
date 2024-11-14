import { CapabilitiesChip, Dropdown, InformationSpan } from '@/components';
import { Box, Grid, Typography } from '@mui/material';
import DirectoryTree from '@/components/DirectoryTree';
import React from 'react';
import { SinglePointMap } from '@/components/Map';
import { directoryListToTree } from '@/app/director/components/index';
import { ServerCapabilitiesTable } from '@/components/ServerCapabilitiesTable';
import { Capabilities, ServerDetailed, ServerGeneral } from '@/types';
import { Capability } from '@/components/configuration';

interface DirectorDropdownProps {
  server: ServerGeneral | ServerDetailed;
  transition: boolean;
}

export const DirectorDropdown = ({
  server,
  transition,
}: DirectorDropdownProps) => {
  return (
    <>
      <Dropdown transition={transition} flexDirection={'column'}>
        <Grid container spacing={1}>
          <Grid item xs={12} md={7}>
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
          <Grid item xs={12} md={5}>
            <Box
              borderRadius={1}
              height={'100%'}
              minHeight={'140px'}
              overflow={'hidden'}
            >
              {transition && (
                <SinglePointMap
                  point={{ lat: server.latitude, lng: server.longitude }}
                />
              )}
            </Box>
          </Grid>
        </Grid>
        <Box sx={{ my: 1 }}>
          <ServerCapabilitiesTable server={server} />
        </Box>
      </Dropdown>
    </>
  );
};

export const CapabilitiesRow = ({
  capabilities,
  parentCapabilities,
}: {
  capabilities: Capabilities;
  parentCapabilities?: Capabilities;
}) => {
  return (
    <Grid container spacing={1}>
      {Object.entries(capabilities).map(([key, value]) => {
        const castKey = key as keyof Capabilities;
        return (
          <Grid item md={12 / 5} sm={12 / 4} xs={12 / 2} key={key}>
            <CapabilitiesChip
              name={key}
              value={value}
              parentValue={
                parentCapabilities ? parentCapabilities[castKey] : undefined
              }
            />
          </Grid>
        );
      })}
    </Grid>
  );
};
