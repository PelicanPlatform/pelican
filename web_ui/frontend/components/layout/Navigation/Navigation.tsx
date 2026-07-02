'use client';

import { StaticNavigationItemProps } from '@/components/layout/Navigation/index';
import useSWR from 'swr';
import { getExportData } from '@/components/DataExportTable';
import { getUser } from '@/helpers/login';
import { Sidebar } from '@/components/layout/Navigation/Sidebar';
import NavigationConfig from '@/app/navigation';
import { getEnabledServers } from '@/helpers/util';
import { Box, Typography } from '@mui/material';
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

  const { data: user } = useSWR('getUser', getUser);
  // /origin_ui/exports is admin-gated server-side (it returns storage
  // credentials and registry edit-URL tokens), so non-admins would
  // 403 every time the navigation mounts. Skip the fetch entirely for
  // them. The only nav item that branches on the response is Globus
  // Configurations, which is admin-only anyway (see allowedRoles in
  // app/navigation.tsx).
  const { data: exports } = useSWR(
    user?.role === 'admin' ? 'getDataExport' : null,
    getExportData,
    { errorRetryCount: 0 }
  );
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

  // Per the operator demo feedback: when running multiple browser
  // tabs as different users, it's easy to forget which one is the
  // privileged session and click "delete user" in the wrong window.
  // A high-contrast top strip makes the admin context unmistakable
  // — different color, different message, fixed at the top so it
  // doesn't scroll away. Non-admins see nothing.
  const isAdmin = user?.authenticated && user?.role === 'admin';

  // Banner height is a fixed pixel value rather than `auto` so
  // everything below can compute its own offset. The strip is one
  // line of small caps text with tight padding — enough to register
  // peripherally without eating real estate from the navigation.
  const ADMIN_BANNER_HEIGHT_PX = 22;
  const topOffset = isAdmin ? ADMIN_BANNER_HEIGHT_PX : 0;

  return (
    <>
      {isAdmin && (
        <Box
          sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            // Below the MUI modal layer (1300) so dialogs still cover
            // the banner when open, but above the sidebar (z-index 2)
            // and burger drawer (1000) so it always wins against the
            // navigation chrome.
            zIndex: 1100,
            height: `${ADMIN_BANNER_HEIGHT_PX}px`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: '#b71c1c', // deep red — distinct from the brand blue
            color: '#fff',
            boxShadow: '0 1px 4px rgba(0,0,0,0.3)',
            pointerEvents: 'none', // pure indicator; never intercepts clicks
          }}
        >
          <Typography
            variant='caption'
            sx={{
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              fontSize: '0.7rem',
              lineHeight: 1,
            }}
          >
            Administrator session
          </Typography>
        </Box>
      )}
      <Box
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', md: 'row' },
          // Push *non-fixed* descendants below the banner. The
          // sidebar and burger drawer manage their own offset via
          // the topOffset prop because they're position: fixed and
          // don't honor parent padding.
          pt: `${topOffset}px`,
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
            topOffset={topOffset}
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
            topOffset={topOffset}
          />
        </Box>
        {children}
      </Box>
    </>
  );
};

export { Navigation };
