import { Box } from '@mui/material';
import { ReactNode } from 'react';

export const PaddedContent = ({ children }: { children: ReactNode }) => {
  return (
    <Box p={2} flexGrow={1}>
      {children}
    </Box>
  );
};
