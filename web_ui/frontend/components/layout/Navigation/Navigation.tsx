'use client';

import {
  NavigationEntry,
  NavigationShellProvider,
  StaticNavigationItemProps,
  isNavigationGroup,
} from '@/components/layout/Navigation/index';
import useSWR from 'swr';
import { getExportData } from '@/components/DataExportTable';
import { getUser } from '@/helpers/login';
import { Sidebar } from '@/components/layout/Navigation/Sidebar';
import NavigationConfig from '@/app/navigation';
import { getServerInfo } from '@/helpers/util';
import { Box } from '@mui/material';
import { AppBar } from '@/components/layout/Navigation/AppBar';
import { ReactNode } from 'react';

/**
 * Recursively removes federationOnly items, pruning any parent or group left
 * standing over nothing.
 */
const filterFederationOnly = (
  entries?: NavigationEntry[]
): NavigationEntry[] | undefined =>
  entries?.flatMap<NavigationEntry>((entry) => {
    if (isNavigationGroup(entry)) {
      const items = filterItems(entry.items);
      return items.length > 0 ? [{ ...entry, items }] : [];
    }
    return filterItems([entry]);
  });

/** Item-level variant. Groups never nest, so below the top level everything is an item. */
const filterItems = (
  items: StaticNavigationItemProps[]
): StaticNavigationItemProps[] =>
  items
    .filter((item) => !item.federationOnly)
    .map((item) =>
      'children' in item
        ? { ...item, children: filterItems(item.children) }
        : item
    )
    .filter((item) => !('children' in item) || item.children.length > 0);

const Navigation = ({
  children,
  config,
  sharedPage,
}: {
  children: ReactNode;
  config?: NavigationEntry[];
  sharedPage?: boolean;
}) => {
  // Check either config or sharedPage is defined but not both
  if ((config && sharedPage) || (!config && !sharedPage)) {
    throw new Error('Either config xor sharedPage must be defined');
  }

  const { data: user, error: userError } = useSWR('getUser', getUser);
  // /origin_ui/exports is admin-gated server-side (it returns storage
  // credentials and registry edit-URL tokens), so non-admins would
  // 403 every time the navigation mounts. Skip the fetch entirely for
  // them. The only nav item that branches on the response is Globus
  // Configurations, which is admin-only anyway (see allowedRoles in
  // app/navigation.tsx).
  const { data: exports, error: exportsError } = useSWR(
    user?.role === 'admin' ? 'getDataExport' : null,
    getExportData,
    { errorRetryCount: 0 }
  );
  const { data: serverInfo, error: serverInfoError } = useSWR(
    'getServerInfo',
    getServerInfo
  );
  const servers = serverInfo?.servers;

  // Everything the visibility rules consult arrives over the network, so until
  // all of it has landed the navigation cannot know which destinations belong
  // to this caller. It holds a placeholder for that window rather than
  // guessing and correcting itself a beat later: a rail that renders eagerly
  // and then drops the rows this caller may not have moves the remaining
  // targets out from under the pointer just as they looked settled.
  //
  // Resolved, not merely finished loading -- an errored fetch has still
  // answered the question, and the rules read an unknown as "not admitted".
  // The exports request is the reason this can't be a single isLoading flag:
  // its key only becomes non-null once /whoami has named an admin, so a
  // fetch-state reading of it is momentarily "idle" before it is "loading",
  // and the rail would flash its full list in between.
  const resolved =
    (user !== undefined || userError !== undefined) &&
    (user?.role !== 'admin' ||
      exports !== undefined ||
      exportsError !== undefined) &&
    (serverInfo !== undefined || serverInfoError !== undefined);

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

  // Drop items whose only audience is a Director or Registry when this server
  // belongs to no federation. Filtering here (rather than inside each
  // NavigationItem) keeps the Sidebar and AppBar renderers in agreement.
  if (serverInfo?.standaloneOrigin) {
    config = filterFederationOnly(config);
  }

  return (
    <NavigationShellProvider>
      <Box id={'navigation'}>
        <Box
          id={'header'}
          sx={{
            flexDirection: { xs: 'column', md: 'row' },
            width: '100%',
          }}
        >
          <Box
            sx={{
              display: { xs: 'none', md: 'block' },
            }}
          >
            <Sidebar
              authenticated={user?.authenticated}
              exportType={exports?.type}
              role={user?.role}
              scopes={user?.scopes}
              config={config as NavigationEntry[]}
              pending={!resolved}
            />
          </Box>
          <Box
            sx={{
              display: { xs: 'block', md: 'none' },
            }}
          >
            <AppBar
              authenticated={user?.authenticated}
              exportType={exports?.type}
              role={user?.role}
              scopes={user?.scopes}
              config={config as NavigationEntry[]}
              pending={!resolved}
            />
          </Box>
          {children}
        </Box>
      </Box>
    </NavigationShellProvider>
  );
};

export { Navigation };
