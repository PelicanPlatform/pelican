import {
  Add,
  Api,
  AppRegistration,
  Article,
  AssistantDirection,
  Block,
  Build,
  Cached,
  CalendarMonth,
  Dashboard,
  Description,
  Equalizer,
  FolderOpen,
  Lock,
  MapOutlined,
  Public,
  Settings,
  Storage,
  TripOrigin,
  Groups,
  Person,
} from '@mui/icons-material';
import { NavigationConfiguration } from '@/components/layout/Navigation';

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
export const SettingsShellScopes = [
  'server.user_admin',
  'pelican.log_read',
];

const NavigationConfig: NavigationConfiguration = {
  settings: [
    {
      title: 'General',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
    },
    {
      title: 'API',
      href: '/settings/api/',
      icon: <Api />,
      allowedRoles: ['admin'],
    },
    {
      // Groups are server-wide (not origin-specific), so they live at a
      // top-level /groups/ route — same as /settings/, /config/, etc.
      // The Settings sidebar surfaces the link here purely for muscle
      // memory; the canonical URL is /groups/.
      title: 'Groups',
      href: '/groups/',
      icon: <Groups />,
    },
    {
      // Reachable by system admins AND user-admins (server.user_admin,
      // possibly granted via group membership). The page's per-row
      // edit/delete affordances stay gated by IsSystemAdminUserID at
      // the API layer, so a user-admin can list and manage non-admin
      // accounts but can't escalate against an existing admin.
      title: 'Users',
      href: '/settings/users/',
      icon: <Person />,
      allowedRoles: ['admin'],
      anyScopes: ['server.user_admin'],
    },
    {
      // System-admin-only: edit the Acceptable Use Policy that every
      // user must accept. Server-side route is gated on AdminAuthHandler;
      // non-admins who navigate here see a forbidden message from the
      // page itself.
      title: 'AUP',
      href: '/settings/aup/',
      icon: <Article />,
      allowedRoles: ['admin'],
    },
    {
      // Log viewer: live in-memory tail of server logs. Reachable by
      // admins AND holders of the dedicated pelican.log_read scope
      // (typically granted via a group), so a user can watch logs
      // without also inheriting admin privileges.
      title: 'Logs',
      href: '/settings/logs/',
      icon: <Description />,
      allowedRoles: ['admin'],
      anyScopes: ['pelican.log_read'],
    },
  ],
  registry: [
    { title: 'Dashboard', href: '/registry/', icon: <Dashboard /> },
    {
      title: 'Add',
      icon: <Add />,
      allowedRoles: ['admin'],
      children: [
        {
          title: 'Namespace',
          href: '/registry/namespace/register/',
          icon: <FolderOpen />,
        },
        {
          title: 'Origin',
          href: '/registry/origin/register/',
          icon: <TripOrigin />,
        },
        {
          title: 'Cache',
          href: '/registry/cache/register/',
          icon: <Storage />,
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
      icon: <CalendarMonth />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Config',
      href: '/config/',
      icon: <Build />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Settings',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
      anyScopes: SettingsShellScopes,
    },
  ],
  origin: [
    { title: 'Dashboard', href: '/origin/', icon: <Dashboard /> },
    {
      title: 'Collections',
      href: '/origin/collections/',
      icon: <FolderOpen />,
    },
    // Groups are server-wide; the canonical URL is /groups/. Surfaced
    // in the origin sidebar for muscle memory.
    { title: 'Groups', href: '/groups/', icon: <Groups /> },
    // The owned-collections page joins "collections I own" with
    // "groups wired to those collections" — a unified ownership view
    // called for in ticket #3298. Visible to any logged-in user;
    // the page itself is empty when the caller owns nothing.
    { title: 'My collections', href: '/origin/owned/', icon: <Person /> },
    {
      title: 'Metrics',
      href: '/origin/metrics/',
      icon: <Equalizer />,
      allowedRoles: ['admin'],
    },
    { title: 'Downtime', href: '/origin/downtime/', icon: <CalendarMonth /> },
    {
      title: 'Globus Configurations',
      href: '/origin/globus/',
      icon: <Public />,
      allowedRoles: ['admin'],
      allowedExportTypes: ['globus'],
    },
    {
      title: 'Issuer',
      href: '/origin/issuer',
      icon: <Lock />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Config',
      href: '/config/',
      icon: <Build />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Settings',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
      anyScopes: SettingsShellScopes,
    },
  ],
  director: [
    { title: 'Dashboard', href: '/director/', icon: <Dashboard /> },
    {
      title: 'Metrics',
      href: '/director/metrics/',
      icon: <Equalizer />,
      allowedRoles: ['admin'],
    },
    { title: 'Downtime', href: '/director/downtime/', icon: <CalendarMonth /> },
    { title: 'Map', href: '/director/map/', icon: <MapOutlined /> },
    {
      title: 'Config',
      href: '/config/',
      icon: <Build />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Settings',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
      anyScopes: SettingsShellScopes,
    },
  ],
  cache: [
    { title: 'Dashboard', href: '/cache/', icon: <Dashboard /> },
    {
      title: 'Metrics',
      href: '/cache/metrics/',
      icon: <Equalizer />,
      allowedRoles: ['admin'],
    },
    { title: 'Downtime', href: '/cache/downtime/', icon: <CalendarMonth /> },
    {
      title: 'Config',
      href: '/config/',
      icon: <Build />,
      allowedRoles: ['admin'],
    },
    {
      title: 'Settings',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
      anyScopes: SettingsShellScopes,
    },
  ],
  shared: [
    { title: 'Origin', href: '/origin/', icon: <TripOrigin /> },
    { title: 'Director', href: '/director/', icon: <AssistantDirection /> },
    { title: 'Registry', href: '/registry/', icon: <AppRegistration /> },
    { title: 'Cache', href: '/cache/', icon: <Cached /> },
    // The shared nav is what /settings/ (and every other server-level
    // page) sees when the process runs multiple server modules. Without
    // a Settings entry here, once a caller lands on a server-level page
    // there's no primary-nav path back into /settings/. Same admittance
    // as the per-subsystem sidebars: admin OR any settings-shell scope.
    {
      title: 'Settings',
      href: '/settings/',
      icon: <Settings />,
      allowedRoles: ['admin'],
      anyScopes: SettingsShellScopes,
    },
  ],
};

export default NavigationConfig;
