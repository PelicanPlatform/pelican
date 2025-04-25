'use client';

import DowntimeCalendar from '../DowntimeCalendar';
import { Box, Button, Grid, Typography } from '@mui/material';
import React, { useContext } from 'react';
import DowntimeList from '@/components/Downtime/Server/DowntimeList';
import {
  DowntimeEditContext,
  DowntimeEditDispatchContext,
} from '@/components/Downtime/DowntimeEditContext';
import EditDowntimePageHeader from '@/components/Downtime/EditDowntimePageHeader';
import { DowntimeModal } from '@/components/Downtime/DowntimeModal';
import DowntimeForm from '@/components/Downtime/Server/DowntimeForm';

const ServerDowntimePage = () => {
  const setDowntime = useContext(DowntimeEditDispatchContext);
  const downtime = useContext(DowntimeEditContext);

  return (
    <>
      <Box>
        <Grid container>
          <Grid item xs={12} lg={12}>
            <EditDowntimePageHeader />
            <Box my={2}>
              <DowntimeCalendar />
            </Box>
            <DowntimeList />
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
