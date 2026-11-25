import { Button } from '@mui/material';
import { Replay } from '@mui/icons-material';
import { useState } from 'react';

import { AlertDispatchContext } from '@/components/AlertProvider';
import { useContext } from 'react';
import { alertOnError } from '@/helpers/util';
import { restartServer } from '@/helpers/api';

export const RestartBox = () => {
  const dispatch = useContext(AlertDispatchContext);
  const [isDisabled, setIsDisabled] = useState(false);

  const handleRestart = async () => {
    setIsDisabled(true);
    try {
      await alertOnError(restartServer, 'Restart Server', dispatch);
    } finally {
      // TODO: Disable button for a given time set by param.Xrootd_ShutdownTimeout.GetDuration().Milliseconds()
      setTimeout(() => {
        setIsDisabled(false);
      }, 60000);
    }
  };

  return (
    <Button
      variant='outlined'
      endIcon={<Replay />}
      onClick={handleRestart}
      disabled={isDisabled}
    >
      Restart Server
    </Button>
  );
};
