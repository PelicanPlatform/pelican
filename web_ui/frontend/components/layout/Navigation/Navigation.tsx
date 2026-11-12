'use client';

import {
  NavigationEntry,
  NavigationShellProvider,
  StaticNavigationItemProps,
  isNavigationGroup,
  useActiveService,
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
  const { data: serverInfo, error: serverInfoError } = useSWR(
    'getServerInfo',
    getServerInfo
  );
  const servers = serverInfo?.servers;
  const { service: lastService, resolved: lastServiceResolved } =
    useActiveService();

  // Server-wide pages (Settings, Groups, Users, Profile) belong to no module,
  // so they borrow the rail of the module the caller came from. Failing that --
  // a fresh tab opened straight onto one, or a remembered module this process
  // no longer runs -- the first module it does run. There used to be a
  // separate "shared" rail listing every module instead, which on a
  // multi-module server swapped the caller's familiar rail for an unrelated
  // one the moment they opened Settings.
  if (sharedPage) {
    const service =
      lastService && servers?.includes(lastService)
        ? lastService
        : servers?.[0];
    config = service ? NavigationConfig[service] : [];
  }

  // Computed from the rail actually shown rather than from `servers`, so a
  // shared page borrowing the cache rail doesn't fetch origin exports just
  // because the process also runs an origin.
  const showsOriginRail =
    !!servers?.includes('origin') && config === NavigationConfig['origin'];

  // /origin_ui/exports is admin-gated server-side (it returns storage
  // credentials and registry edit-URL tokens), so non-admins would
  // 403 every time the navigation mounts. Skip the fetch entirely for
  // them. It is also origin-only: the sole nav item that branches on the
  // response is the origin rail's Globus Configurations (admin-only too;
  // see allowedRoles in app/navigation.tsx), so on a director, registry,
  // cache, or transfer server the request could only ever fail -- and
  // `resolved` below would hold the whole rail in skeleton while it did.
  const { data: exports, error: exportsError } = useSWR(
    user?.role === 'admin' && showsOriginRail ? 'getDataExport' : null,
    getExportData,
    { errorRetryCount: 0 }
  );

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
  // its key only becomes non-null once /whoami has named an admin and
  // /servers has named an origin, so a fetch-state reading of it is
  // momentarily "idle" before it is "loading", and the rail would flash its
  // full list in between. The wait applies only where the fetch does: an
  // admin on a rail other than the origin's has nothing to wait for.
  //
  // A shared page also waits for the remembered module, which is read from
  // session storage after mount; without that it would draw the fallback
  // module's rail and then swap to the right one.
  const resolved =
    (user !== undefined || userError !== undefined) &&
    (serverInfo !== undefined || serverInfoError !== undefined) &&
    (!sharedPage || lastServiceResolved) &&
    (user?.role !== 'admin' ||
      !showsOriginRail ||
      exports !== undefined ||
      exportsError !== undefined);

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
