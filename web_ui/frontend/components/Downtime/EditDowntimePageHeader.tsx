import React, { useContext } from 'react';
import { DowntimeEditDispatchContext } from '@/components/Downtime/DowntimeEditContext';
import { Box, Button, Typography } from '@mui/material';
import { CalendarDateTimeContext } from '@/components/Downtime/CalendarContext';

const EditDowntimePageHeader = () => {
  const setDowntime = useContext(DowntimeEditDispatchContext);
  const range = useContext(CalendarDateTimeContext);

  return (
    <Box
      display={'flex'}
      flexDirection={'row'}
      justifyContent={'space-between'}
    >
      <Typography variant={'h4'}>Service Downtime</Typography>
      <Button
        variant={'contained'}
        color={'primary'}
        onClick={() => {
          console.log('test');
          setDowntime({
            startTime: range.startTime,
            endTime: range.endTime,
          });
        }}
      >
        Create Downtime
      </Button>
    </Box>
  );
};

export default EditDowntimePageHeader;
