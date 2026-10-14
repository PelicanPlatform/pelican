import {
  AccountTree,
  Add,
  AdminPanelSettings,
  Api,
  AppRegistration,
  AssistantDirection,
  Block,
  Bookmarks,
  Cached,
  Dashboard,
  EventBusy,
  FolderOpen,
  FormatListBulleted,
  Gavel,
  Groups,
  Hub,
  Insights,
  Inventory2,
  Key,
  ManageAccounts,
  Map,
  Settings,
  SwapHoriz,
  Terminal,
  Token,
  TripOrigin,
  Tune,
} from '@mui/icons-material';

import {
  NavigationConfiguration,
  NavigationGroupProps,
  StaticNavigationChildItemProps,
} from '@/components/layout/Navigation';

// SettingsShellScopes is the union of scopes admitted into the /settings/
// shell by app/settings/layout.tsx. Anyone the shell would let in needs a
// visible path there from every subsystem sidebar, otherwise a scope-only
// holder can reach Settings only by typing the URL. Keep this list and the
// layout's `anyScopes` in sync; both surfaces import from here so a future
// scope addition lands in one place.
//
// Excluded on purpose: server.admin. Admins are admitted by the role gate
// (`allowedRoles: ['admin']`), so listing the scope here would be
// redundant.
//
// server.user_admin was dropped when user administration moved out to
// /users/: a user-admin holding only that scope now reaches Users directly
// from the rail and has nothing to see inside the Settings shell, so
// admitting them there would only offer an empty page.
export const SettingsShellScopes = ['pelican.log_read'];

// Every module used to repeat a Config entry and a Settings entry at the foot
// of its rail -- ten slots across the app for two destinations, and the reason
// the wrench and the gear sat side by side looking like the same thing twice.
// Both are server-wide rather than module-specific, so they collapse into a
// single Administration entry that lands on the Settings shell, which already
// renders its own sub-navigation. Config now lives inside that sub-navigation
// (see `settings` below) rather than in every rail.
const Administration: StaticNavigationChildItemProps = {
  title: 'Administration',
  href: '/settings/',
  icon: <AdminPanelSettings />,
  allowedRoles: ['admin'],
  anyScopes: SettingsShellScopes,
};

// Groups and Users are server-wide rather than module-specific, and they are
// primary destinations rather than entries in the administration menu: both
// were reachable only through the Settings sub-navigation, which meant
// arriving at one shrank the rail and left you on a page the visible menu
// couldn't represent. They now sit in every module rail under an Access
// heading -- who may do what -- which on the origin also holds the Issuer and
// Globus entries that govern the same question.
const AccessItems: StaticNavigationChildItemProps[] = [
  // Canonical URL is /groups/ -- top level, like /users/ and /settings/.
  // The page admits every signed-in caller, so it carries no role; the flag
  // is what keeps it out of an anonymous caller's rail.
  { title: 'Groups', href: '/groups/', icon: <Groups />, requiresLogin: true },
  {
    // Reachable by system admins AND user-admins (server.user_admin,
    // possibly granted via group membership). The page's per-row
    // edit/delete affordances stay gated by IsSystemAdminUserID at the API
    // layer, so a user-admin can list and manage non-admin accounts but
    // can't escalate against an existing admin.
    //
    // `ManageAccounts` rather than `Person`, which this used to share with
    // the origin's "My Collections" entry -- administering accounts and
    // owning things are not the same idea and should not be the same glyph.
    title: 'Users',
    href: '/users/',
    icon: <ManageAccounts />,
    allowedRoles: ['admin'],
    anyScopes: ['server.user_admin'],
  },
];

const Access: NavigationGroupProps = {
  group: 'Access',
  items: AccessItems,
};

// Administration stands alone under its heading: it is the one destination
// that is about the server itself rather than who may use it, and folding it
// into Access would blur the heading that makes the other two legible.
const Server: NavigationGroupProps = {
  group: 'Server',
  items: [Administration],
};

const NavigationConfig: NavigationConfiguration = {
  settings: [
    {
      // Exact: this is the shell's own landing page, not the whole shell.
      // Without it, "General" would stay lit while you are on Users or Logs.
      // The rail's Administration entry shares this href precisely because it
      // *does* stand for the whole section, and so matches by prefix.
      title: 'General',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
      exactMatch: true,
    },
    {
      // Config was previously only reachable from the subsystem rails. Now
      // that Administration replaces those entries, the Settings shell is
      // where it has to live -- without this the /config/ page has no link
      // anywhere in the UI. `Tune` rather than the old `Build`, which was
      // a second spanner-and-gear metaphor sitting next to Settings.
      title: 'Config',
      href: '/settings/config/',
      icon: <Tune />,
      allowedRoles: ['admin'],
    },
    {
      title: 'API',
      href: '/settings/api/',
      icon: <Api />,
      allowedRoles: ['admin'],
    },
    {
      // System-admin-only: edit the Acceptable Use Policy that every
      // user must accept. Server-side route is gated on AdminAuthHandler;
      // non-admins who navigate here see a forbidden message from the
      // page itself.
      //
      // `Gavel` says policy. The old `Article` was a sheet of paper, all but
      // indistinguishable from the `Description` glyph on Logs directly below.
      title: 'AUP',
      href: '/settings/aup/',
      icon: <Gavel />,
      allowedRoles: ['admin'],
    },
    {
      // Log viewer: live in-memory tail of server logs. Reachable by
      // admins AND holders of the dedicated pelican.log_read scope
      // (typically granted via a group), so a user can watch logs
      // without also inheriting admin privileges.
      title: 'Logs',
      href: '/settings/logs/',
      icon: <Terminal />,
      allowedRoles: ['admin'],
      anyScopes: ['pelican.log_read'],
    },
  ],
  registry: [
    {
      title: 'Dashboard',
      href: '/registry/',
      icon: <Dashboard />,
      exactMatch: true,
    },
    {
      title: 'Add',
      icon: <Add />,
      allowedRoles: ['admin'],
      children: [
        {
          // A namespace is a hierarchy, not a directory -- and `FolderOpen`
          // was already doing duty for the origin's Object Browser.
          title: 'Namespace',
          href: '/registry/namespace/register/',
          icon: <AccountTree />,
        },
        {
          title: 'Origin',
          href: '/registry/origin/register/',
          icon: <TripOrigin />,
        },
        {
          // Matches the glyph the shared rail uses for Cache. The same
          // concept had two icons one menu apart.
          title: 'Cache',
          href: '/registry/cache/register/',
          icon: <Cached />,
        },
      ],
    },
    {
      title: 'Denied Namespaces',
      href: '/registry/denied/',
      icon: <Block />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Downtime',
      href: '/registry/downtime/',
      icon: <EventBusy />,
      allowedRoles: ['admin'],
    },
    Access,
    Server,
  ],
  // Origin is the only module with enough destinations to need grouping: nine,
  // where a rail is sized for a handful. Three labelled clusters read far
  // faster than one nine-item stack.
  origin: [
    {
      // The origin dashboard shows export paths and registration status,
      // so unlike the other dashboards its page redirects anonymous callers
      // to sign in.
      title: 'Dashboard',
      href: '/origin/',
      icon: <Dashboard />,
      exactMatch: true,
      requiresLogin: true,
    },
    {
      group: 'Data',
      items: [
        {
          title: 'Object Browser',
          href: '/origin/client/',
          icon: <FolderOpen />,
        },
        {
          // The two collection views are the same list under different
          // scopes, so they sit under one heading rather than as unrelated
          // siblings. A collection is a curated set rather than a directory,
          // which frees `FolderOpen` for the browser that really is one.
          title: 'Collections',
          icon: <Inventory2 />,
          children: [
            {
              // Both collection pages admit any signed-in user; neither is
              // reachable anonymously.
              title: 'All Collections',
              href: '/origin/collections/',
              icon: <FormatListBulleted />,
              requiresLogin: true,
            },
            {
              // The owned-collections page joins "collections I own" with
              // "groups wired to those collections" -- a unified ownership
              // view called for in ticket #3298. Visible to any logged-in
              // user; the page itself is empty when the caller owns nothing.
              //
              // The page is about ownership, not people, so it no longer
              // borrows the `Person` glyph that Settings uses for user
              // administration.
              title: 'My Collections',
              href: '/origin/owned/',
              icon: <Bookmarks />,
              requiresLogin: true,
            },
          ],
        },
      ],
    },
    {
      group: 'Monitoring',
      items: [
        {
          // Listed twice before this cleanup -- once ungated and once
          // admin-only -- so admins saw the same destination rendered as two
          // identical icons four slots apart. Deduplicated to the ungated
          // entry, which is the one that decided who actually saw the link.
          title: 'Metrics',
          href: '/origin/metrics/',
          icon: <Insights />,
        },
        {
          // Origin downtime exists so the Director can route around this
          // server and the Registry can persist the record; a standalone
          // Origin has neither.
          title: 'Downtime',
          href: '/origin/downtime/',
          icon: <EventBusy />,
          federationOnly: true,
        },
      ],
    },
    {
      group: 'Access',
      items: [
        ...AccessItems,
        {
          // An issuer mints tokens. The old padlock said "this is secure",
          // which is true of every page in the UI.
          title: 'Issuer',
          href: '/origin/issuer/',
          icon: <Token />,
          allowedRoles: ['admin'],
        },
        {
          // A transfer integration, not a globally-visible thing -- the globe
          // is better saved for federation-wide concepts.
          title: 'Globus',
          href: '/origin/globus/',
          icon: <Hub />,
          allowedRoles: ['admin'],
          allowedExportTypes: ['globus'],
        },
      ],
    },
    Server,
  ],
  director: [
    {
      title: 'Dashboard',
      href: '/director/',
      icon: <Dashboard />,
      exactMatch: true,
    },
    {
      title: 'Metrics',
      href: '/director/metrics/',
      icon: <Insights />,
      allowedRoles: ['admin'],
    },
    { title: 'Downtime', href: '/director/downtime/', icon: <EventBusy /> },
    // Filled `Map`, not `MapOutlined`: fill is the channel that distinguishes
    // the active destination from the resting ones, so it can't also be
    // spent on one arbitrary item.
    { title: 'Map', href: '/director/map/', icon: <Map /> },
    Access,
    Server,
  ],
  cache: [
    {
      title: 'Dashboard',
      href: '/cache/',
      icon: <Dashboard />,
      exactMatch: true,
    },
    {
      title: 'Metrics',
      href: '/cache/metrics/',
      icon: <Insights />,
      allowedRoles: ['admin'],
    },
    { title: 'Downtime', href: '/cache/downtime/', icon: <EventBusy /> },
    Access,
    Server,
  ],
  transfer: [
    {
      title: 'Dashboard',
      href: '/transfer/',
      icon: <Dashboard />,
      exactMatch: true,
    },
    { title: 'Jobs', href: '/transfer/jobs/', icon: <SwapHoriz /> },
    { title: 'Credentials', href: '/transfer/credentials/', icon: <Key /> },
    // Transfer's Config and Settings entries carried no role gate, unlike
    // every other module's. The Settings shell redirects non-admins away, so
    // the ungated links only ever offered a door that closes on you; the
    // shared Administration entry gates them like everywhere else.
    Access,
    Server,
  ],
  shared: [
    { title: 'Origin', href: '/origin/', icon: <TripOrigin /> },
    { title: 'Director', href: '/director/', icon: <AssistantDirection /> },
    { title: 'Registry', href: '/registry/', icon: <AppRegistration /> },
    { title: 'Cache', href: '/cache/', icon: <Cached /> },
    // The shared nav is what /settings/ (and every other server-level
    // page) sees when the process runs multiple server modules. Without
    // an Administration entry here, once a caller lands on a server-level
    // page there's no primary-nav path back into /settings/.
    Access,
    Server,
  ],
};

export default NavigationConfig;
