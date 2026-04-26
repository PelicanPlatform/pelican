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

const NavigationConfig: NavigationConfiguration = {
  settings: [
    {
      title: 'General',
      href: '/settings/',
      icon: <Settings />,
    },
    {
      title: 'API',
      href: '/settings/api/',
      icon: <Api />,
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
      title: 'Users',
      href: '/settings/users/',
      icon: <Person />,
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
    },
  ],
  origin: [
    { title: 'Dashboard', href: '/origin/', icon: <Dashboard /> },
    { title: 'Collections', href: '/origin/collections/', icon: <FolderOpen /> },
    // Groups are server-wide; the canonical URL is /groups/. Surfaced
    // in the origin sidebar for muscle memory.
    { title: 'Groups', href: '/groups/', icon: <Groups /> },
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
    },
  ],
  shared: [
    { title: 'Origin', href: '/origin/', icon: <TripOrigin /> },
    { title: 'Director', href: '/director/', icon: <AssistantDirection /> },
    { title: 'Registry', href: '/registry/', icon: <AppRegistration /> },
    { title: 'Cache', href: '/cache/', icon: <Cached /> },
  ],
};

export default NavigationConfig;
