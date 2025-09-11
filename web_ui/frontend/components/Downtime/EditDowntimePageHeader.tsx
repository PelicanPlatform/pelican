import React, { useContext } from 'react';
import { DowntimeEditDispatchContext } from '@/components/Downtime/DowntimeEditContext';
import { Box, Button, Typography } from '@mui/material';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

const EditDowntimePageHeader = () => {
  const setDowntime = useContext(DowntimeEditDispatchContext);

  return (
    <Box
      display={'flex'}
      flexDirection={'row'}
      justifyContent={'space-between'}
    >
      <Typography variant={'h4'}>Service Downtime</Typography>
      <AuthenticatedContent allowedRoles={['admin']}>
        <Button
          variant={'contained'}
          color={'primary'}
          onClick={() => {
            setDowntime({});
          }}
        >
          Create Downtime
        </Button>
      </AuthenticatedContent>
    </Box>
  );
};

export default EditDowntimePageHeader;
