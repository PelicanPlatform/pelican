import { Institution } from '@/components/Config/index.d';
import React from 'react';
import { IconButton, Modal, Portal, Typography } from '@mui/material';
import { Box, Button, TextField } from '@mui/material';

import { ModalProps } from '@/components/Config/ObjectField/ObjectField';
import { ClickAwayListener } from '@mui/base';
import { Close } from '@mui/icons-material';

const ObjectModal = ({ name, open, handleClose, children }: ModalProps) => {
  return (
    <Modal open={open} onClose={handleClose}>
      <Box
        sx={{
          height: '100vh',
          display: 'flex',
        }}
      >
        <Box
          sx={{
            maxHeight: '100vh',
            m: 'auto',
            p: 2,
            bgcolor: 'white',
            borderRadius: 1,
            overflowY: 'auto',
            height: {
              xs: '100%',
              md: 'auto',
            },
            width: {
              xs: '100%',
              md: 'auto',
            },
          }}
        >
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
            }}
          >
            <Box my={'auto'}>
              <Typography variant={'h6'}>{name}</Typography>
            </Box>
            <IconButton onClick={handleClose}>
              <Close />
            </IconButton>
          </Box>
          <Box
            sx={{
              overflowY: 'auto',
            }}
          >
            {children}
          </Box>
        </Box>
      </Box>
    </Modal>
  );
};

export default ObjectModal;
