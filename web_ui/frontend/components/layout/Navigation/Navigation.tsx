'use client';

import { StaticNavigationItemProps } from '@/components/layout/Navigation/index';
import useSWR from 'swr';
import { getExportData } from '@/components/DataExportTable';
import { getUser } from '@/helpers/login';
import { Sidebar } from '@/components/layout/Navigation/Sidebar';
import NavigationConfig from '@/app/navigation';
import { getEnabledServers } from '@/helpers/util';
import { Box } from '@mui/material';
import { AppBar } from '@/components/layout/Navigation/AppBar';
import { ReactNode } from 'react';

const Navigation = ({
  children,
  config,
  sharedPage,
}: {
  children: ReactNode;
  config?: StaticNavigationItemProps[];
  sharedPage?: boolean;
}) => {
  // Check either config or sharedPage is defined but not both
  if ((config && sharedPage) || (!config && !sharedPage)) {
    throw new Error('Either config xor sharedPage must be defined');
  }

  const { data: exports } = useSWR('getDataExport', getExportData);
  const { data: user } = useSWR('getUser', getUser);
  const { data: servers } = useSWR('getServers', getEnabledServers);

  // Handle navigation for shared pages
  // Best we can do is sending them to root if there are many running servers
  // If there is just one then we can render that navigation
  if (sharedPage) {
    const multipleServersActive = servers && servers.length > 1;
    if (multipleServersActive) {
      config = NavigationConfig['shared'];
    } else {
      config = NavigationConfig[servers ? servers[0] : 'shared'];
    }
  }

  console.log(user);

  return (
    <>
      <Box
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', md: 'row' },
        }}
      >
        <Box
          sx={{
            display: { xs: 'none', md: 'block' },
          }}
        >
          <Sidebar
            exportType={exports?.type}
            role={user?.role}
            config={config as StaticNavigationItemProps[]}
          />
        </Box>
        <Box
          sx={{
            display: { xs: 'block', md: 'none' },
          }}
        >
          <AppBar
            exportType={exports?.type}
            role={user?.role}
            config={config as StaticNavigationItemProps[]}
          />
        </Box>
        {children}
      </Box>
    </>
  );
};

export { Navigation };
