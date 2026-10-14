'use client';

import { Box, Link } from '@mui/material';
import { ReactNode } from 'react';

import { useRailMetrics } from '@/components/layout/Navigation';

interface MainProps {
  children: ReactNode;
  displayMaxmindAttribution?: boolean;
}

export const Main = ({
  children,
  displayMaxmindAttribution = false,
}: MainProps) => {
  const { width } = useRailMetrics();

  return (
    <Box display={'flex'} flexDirection={'column'} flexGrow={1}>
      <Box
        component={'main'}
        pl={0}
        // Clears the rail. Reads the rail's own current width rather than
        // repeating the number, so the two cannot drift apart -- including
        // when the rail shrinks to make room for a sub-navigation.
        ml={{ xs: 0, ...width }}
        sx={{
          transition: (theme) =>
            theme.transitions.create('margin-left', {
              duration: theme.transitions.duration.shorter,
            }),
        }}
        display={'flex'}
        minHeight={'100vh'}
        flexGrow={1}
        zIndex={1}
      >
        {children}
      </Box>
      {displayMaxmindAttribution && (
        <Box p={2} display={'flex'}>
          <Link mx={'auto'} href='https://www.maxmind.com/en/home'>
            Free IP geolocation by MaxMind
          </Link>
        </Box>
      )}
    </Box>
  );
};

export default Main;
