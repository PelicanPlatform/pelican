import { Button } from '@mui/material';
import { Replay } from '@mui/icons-material';

import { AlertDispatchContext } from '@/components/AlertProvider';
import { useContext } from 'react';
import { alertOnError } from '@/helpers/util';
import { restartServer } from '@/helpers/api';

export const RestartBox = () => {
  const dispatch = useContext(AlertDispatchContext);

  return (
    <Button
      variant='outlined'
      endIcon={<Replay />}
      onClick={() => alertOnError(restartServer, 'Restart Server', dispatch)}
    >
      Restart Server
    </Button>
  );
};
