import { Box } from '@mui/material';
import { ReactNode } from 'react';

export const Main = ({ children }: { children: ReactNode }) => {
  return (
    <Box
      component={'main'}
      p={2}
      pl={0}
      ml={'90px'}
      display={'flex'}
      minHeight={'100vh'}
      flexGrow={1}
      zIndex={1}
    >
      {children}
    </Box>
  );
};

export default Main;
