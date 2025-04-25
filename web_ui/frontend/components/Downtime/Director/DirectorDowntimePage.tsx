'use client';

import DowntimeCalendar from '../DowntimeCalendar';
import { Box, Grid } from '@mui/material';
import React from 'react';
import DirectorDowntimeList from './DirectorDowntimeList';
import { CalendarDateTimeProvider } from '@/components/Downtime/CalendarContext';
import DirectorDowntimePageHeader from './DirectorDowntimePageHeader';
import useApiSWR from '@/hooks/useApiSWR';
import { DowntimeGet } from '@/types';
import { DirectorDowntimeKey, ServerDowntimeKey } from '@/components/Downtime';
import { getDirectorDowntime, getDowntime } from '@/helpers/api';

const ServerDowntimePage = () => {
  const { data } = useApiSWR<DowntimeGet[]>(
    'Failed to fetch downtimes',
    DirectorDowntimeKey,
    getDirectorDowntime
  );

  return (
    <CalendarDateTimeProvider>
      <Box>
        <Grid container>
          <Grid item xs={12} lg={12}>
            <DirectorDowntimePageHeader />
            <Box my={2}>
              <DowntimeCalendar data={data} />
            </Box>
            <DirectorDowntimeList data={data} />
          </Grid>
        </Grid>
      </Box>
    </CalendarDateTimeProvider>
  );
};

export default ServerDowntimePage;
