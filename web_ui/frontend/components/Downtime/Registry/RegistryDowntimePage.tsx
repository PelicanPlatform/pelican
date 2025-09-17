'use client';

import DowntimeCalendar from '../DowntimeCalendar';
import { Box, Grid } from '@mui/material';
import React, { useContext, useEffect } from 'react';
import RegistryDowntimeList from './RegistryDowntimeList';
import {
  DowntimeEditContext,
  DowntimeEditDispatchContext,
} from '@/components/Downtime/DowntimeEditContext';
import EditDowntimePageHeader from '@/components/Downtime/EditDowntimePageHeader';
import { DowntimeModal } from '@/components/Downtime/DowntimeModal';
import ServerUnknownDowntimeForm from './ServerUnknownDowntimeForm';
import useApiSWR from '@/hooks/useApiSWR';
import { DowntimeGet } from '@/types';
import { ServerDowntimeKey } from '@/components/Downtime';
import { getDowntime } from '@/helpers/api';

const ServerDowntimePage = () => {
  const setDowntime = useContext(DowntimeEditDispatchContext);
  const downtime = useContext(DowntimeEditContext);

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const searchParamServerName = searchParams.get('serverName');
    if (searchParamServerName !== null) {
      setDowntime({
        startTime: Date.now(),
        endTime: Date.now(),
        serverName: searchParamServerName,
      });
    }
  }, [setDowntime]);

  const { data } = useApiSWR<DowntimeGet[]>(
    'Failed to fetch downtimes',
    ServerDowntimeKey,
    getDowntime
  );

  return (
    <>
      <Box>
        <Grid container>
          <Grid
            size={{
              xs: 12,
              lg: 12,
            }}
          >
            <EditDowntimePageHeader />
            <Box my={2}>
              <DowntimeCalendar data={data} />
            </Box>
            <RegistryDowntimeList data={data} />
          </Grid>
        </Grid>
      </Box>
      <DowntimeModal
        open={downtime !== undefined}
        onClose={() => setDowntime(undefined)}
      >
        {downtime && (
          <ServerUnknownDowntimeForm
            downtime={downtime}
            onSuccess={() => setDowntime(undefined)}
          />
        )}
      </DowntimeModal>
    </>
  );
};

export default ServerDowntimePage;
