'use client';

import DowntimeCalendar from '../DowntimeCalendar';
import { Box, Grid } from '@mui/material';
import React, { useContext } from 'react';
import DowntimeList from '@/components/Downtime/Server/DowntimeList';
import {
  DowntimeEditContext,
  DowntimeEditDispatchContext,
} from '@/components/Downtime/DowntimeEditContext';
import EditDowntimePageHeader from '@/components/Downtime/EditDowntimePageHeader';
import { DowntimeModal } from '@/components/Downtime/DowntimeModal';
import DowntimeForm from '@/components/Downtime/Server/DowntimeForm';
import useApiSWR from '@/hooks/useApiSWR';
import { DowntimeGet } from '@/types';
import { ServerDowntimeKey } from '@/components/Downtime';
import { getDowntime } from '@/helpers/api';

const ServerDowntimePage = () => {
  const setDowntime = useContext(DowntimeEditDispatchContext);
  const downtime = useContext(DowntimeEditContext);

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
              lg: 12
            }}>
            <EditDowntimePageHeader />
            <Box my={2}>
              <DowntimeCalendar data={data} />
            </Box>
            <DowntimeList data={data} />
          </Grid>
        </Grid>
      </Box>
      <DowntimeModal
        open={downtime !== undefined}
        onClose={() => setDowntime(undefined)}
      >
        {downtime && (
          <DowntimeForm
            downtime={downtime}
            onSuccess={() => setDowntime(undefined)}
          />
        )}
      </DowntimeModal>
    </>
  );
};

export default ServerDowntimePage;
