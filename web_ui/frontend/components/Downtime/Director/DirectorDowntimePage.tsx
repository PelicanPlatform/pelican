'use client';

import DowntimeCalendar from '../DowntimeCalendar';
import { Box, Grid } from '@mui/material';
import React from 'react';
import DirectorDowntimeList from './DirectorDowntimeList';
import { CalendarDateTimeProvider } from '@/components/Downtime/CalendarContext';
import DirectorDowntimePageHeader from './DirectorDowntimePageHeader';

const ServerDowntimePage = () => {
  return (
    <CalendarDateTimeProvider>
      <Box>
        <Grid container>
          <Grid item xs={12} lg={12}>
            <DirectorDowntimePageHeader />
            <Box my={2}>
              <DowntimeCalendar />
            </Box>
            <DirectorDowntimeList />
          </Grid>
        </Grid>
      </Box>
    </CalendarDateTimeProvider>
  );
};

export default ServerDowntimePage;
