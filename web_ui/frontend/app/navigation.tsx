import {
  Add,
  Block,
  Build,
  Dashboard,
  Equalizer,
  FolderOpen,
  Lock,
  MapOutlined,
  Public,
  Storage,
  TripOrigin,
  AssistantDirection,
  AppRegistration,
  Cached,
  Api,
  Settings,
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
  ],
  registry: [
    { title: 'Dashboard', href: '/registry/', icon: <Dashboard /> },
    {
      title: 'Denied Namespaces',
      href: '/registry/denied/',
      icon: <Block />,
      allowedRoles: ['admin'],
    },
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
    { title: 'Metrics', href: '/origin/metrics/', icon: <Equalizer /> },
    {
      title: 'Globus Configurations',
      href: '/origin/globus/',
      icon: <Public />,
      allowedExportTypes: ['globus'],
    },
    { title: 'Issuer', href: '/origin/issuer', icon: <Lock /> },
    { title: 'Config', href: '/config/', icon: <Build /> },
    { title: 'Settings', href: '/settings/', icon: <Settings /> },
  ],
  director: [
    { title: 'Dashboard', href: '/director/', icon: <Dashboard /> },
    {
      title: 'Metrics',
      href: '/director/metrics/',
      icon: <Equalizer />,
      allowedRoles: ['admin'],
    },
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
    { title: 'Metrics', href: '/cache/metrics/', icon: <Equalizer /> },
    { title: 'Config', href: '/config/', icon: <Build /> },
    { title: 'Settings', href: '/settings/', icon: <Settings /> },
  ],
  shared: [
    { title: 'Origin', href: '/origin/', icon: <TripOrigin /> },
    { title: 'Director', href: '/director/', icon: <AssistantDirection /> },
    { title: 'Registry', href: '/registry/', icon: <AppRegistration /> },
    { title: 'Cache', href: '/cache/', icon: <Cached /> },
  ],
};

export default NavigationConfig;
