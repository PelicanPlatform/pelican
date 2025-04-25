/**
 * Used to display the modal for entering the downtime information
 */

import { Box, IconButton, Modal, Paper, Typography } from '@mui/material';
import { Close } from '@mui/icons-material';
import { ReactNode } from 'react';

interface DowntimeModalProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}

export const DowntimeModal = ({
  open,
  onClose,
  children,
}: DowntimeModalProps) => {
  return (
    <Modal open={open} onClose={onClose}>
      <Paper sx={style}>
        <Box
          display={'flex'}
          flexDirection={'row'}
          justifyContent={'space-between'}
          alignItems={'center'}
        >
          <Typography variant={'h5'}>Create Downtime</Typography>
          <IconButton onClick={onClose}>
            <Close />
          </IconButton>
        </Box>
        <hr />
        {children}
      </Paper>
    </Modal>
  );
};

const style = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  bgcolor: 'background.paper',
  borderRadius: 1,
  p: 2,
  width: '600px',
  maxWidth: '100%',
};
