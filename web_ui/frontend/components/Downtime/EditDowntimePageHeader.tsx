import React, { useContext } from 'react';
import useSWR from 'swr';
import { DowntimeEditDispatchContext } from '@/components/Downtime/DowntimeEditContext';
import { Box, Button, Typography } from '@mui/material';
import { getUser } from '@/helpers/login';

const EditDowntimePageHeader = () => {
  const setDowntime = useContext(DowntimeEditDispatchContext);
  const { data: user } = useSWR('getUser', getUser);

  return (
    <Box
      display={'flex'}
      flexDirection={'row'}
      justifyContent={'space-between'}
    >
      <Typography variant={'h4'}>Service Downtime</Typography>
      {user?.role === 'admin' && (
        <Button
          variant={'contained'}
          color={'primary'}
          onClick={() => {
            setDowntime({});
          }}
        >
          Create Downtime
        </Button>
      )}
    </Box>
  );
};

export default EditDowntimePageHeader;
