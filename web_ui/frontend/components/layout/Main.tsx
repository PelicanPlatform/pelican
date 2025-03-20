import { Box, Link } from '@mui/material';
import { ReactNode } from 'react';

interface MainProps {
  children: ReactNode
  displayMaxmindAttribution?: boolean
}

export const Main = ({ children, displayMaxmindAttribution = false }: MainProps) => {
  return (
    <Box
      display={"flex"}
      flexDirection={"column"}
      flexGrow={1}
    >
      <Box
        component={'main'}
        pl={0}
        ml={{ xs: 0, md: '72px' }}
        display={'flex'}
        minHeight={'100vh'}
        flexGrow={1}
        zIndex={1}
      >
        {children}
      </Box>
      {
        displayMaxmindAttribution &&
        <Box p={2} display={"flex"}>
          <Link mx={"auto"} href='https://www.maxmind.com/en/home'>Free IP geolocation by MaxMind</Link>
        </Box>
      }
    </Box>
  );
};

export default Main;
