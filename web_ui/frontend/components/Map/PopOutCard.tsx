import React, { FC, ReactNode, useEffect } from 'react';
import { Box, Grow, IconButton, Typography } from '@mui/material';
import { Close } from '@mui/icons-material';

const PopOutCard = ({
  title,
  children,
  active,
  onClose,
}: {
  title?: string;
  children: ReactNode;
  active: boolean;
  onClose: () => void;
}) => {
  useEffect(() => {
    if (active) {
      const handler = (event: KeyboardEvent) => {
        if (event.key == 'Escape') {
          onClose();
        }
      };
      document.addEventListener('keydown', handler);
      return () => {
        document.removeEventListener('keydown', handler);
      };
    }
  }, []);

  return (
    <Grow in={active} style={{ transformOrigin: '100% 0 0' }}>
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          right: 0,
          zIndex: 99,
          maxWidth: { xs: '100vw', md: '50vw' },
          m: { xs: 0, md: 1 },
          borderRadius: 1,
          borderColor: 'white',
          p: 1,
        }}
        bgcolor={'white'}
        p={1}
      >
        <Box display={'flex'}>
          <Typography variant={'h6'}>{title}</Typography>
          <CloseButton onClose={onClose} />
        </Box>
        {children}
      </Box>
    </Grow>
  );
};

const CloseButton = ({ onClose }: { onClose: () => void }) => {
  return (
    <IconButton onClick={onClose} sx={{ ml: 'auto' }} size={'small'}>
      <Close />
    </IconButton>
  );
};

export default PopOutCard;
