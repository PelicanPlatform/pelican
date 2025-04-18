/**
 * Used to display the modal for entering the downtime information
 */

import DowntimeForm from './DowntimeForm';
import { Box, IconButton, Modal, Paper, Typography } from '@mui/material';
import { Close } from '@mui/icons-material';
import { DowntimeGet, DowntimePost } from '@/types';

interface DowntimeModalProps {
  open: boolean;
  onClose: () => void;
  downtime:
    | DowntimeGet
    | Omit<DowntimePost, 'severity' | 'class' | 'description'>;
}

export const DowntimeModal = ({
  open,
  onClose,
  downtime,
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
        <DowntimeForm downtime={downtime} onSuccess={() => onClose()} />
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
