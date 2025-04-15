'use client';

import DowntimeCalendar from './DowntimeCalendar';
import { Box, Button, Grid, Typography } from '@mui/material';
import React, { useContext } from 'react';
import DowntimeList from '@/components/Downtime/ServerDowntime/DowntimeList';
import { DowntimeEditProvider } from '@/components/Downtime/DowntimeEditContext';
import { CalendarDateTimeProvider } from '@/components/Downtime/CalendarContext';
import ServerDowntimePageHeader from '@/components/Downtime/ServerDowntime/ServerDowntimePageHeader';

const ServerDowntimePage = () => {
  return (
    <DowntimeEditProvider>
      <CalendarDateTimeProvider>
        <Box>
          <Grid container>
            <Grid item xs={12} lg={12}>
              <ServerDowntimePageHeader />
              <Box my={2}>
                <DowntimeCalendar />
              </Box>
              <DowntimeList />
            </Grid>
          </Grid>
        </Box>
      </CalendarDateTimeProvider>
    </DowntimeEditProvider>
  );
};

export default ServerDowntimePage;
