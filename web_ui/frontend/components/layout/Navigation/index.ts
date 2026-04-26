import { ServerType, User } from '@/index';
import { ReactNode } from 'react';
import { ExportRes } from '@/components/DataExportTable';

export { Navigation } from './Navigation';

export type NavigationConfiguration = {
  [key in ServerType | 'shared' | 'settings']: StaticNavigationItemProps[];
};

export type StaticNavigationItemProps =
  | StaticNavigationParentItemProps
  | StaticNavigationChildItemProps;

export type StaticNavigationBaseItemProps = {
  title: string | (() => string);
  icon: ReactNode;
  showTitle?: boolean;
  allowedRoles?: User['role'][];
  // anyScopes lets a nav item show for callers holding any of these
  // effective scopes, in addition to allowedRoles. Either matching
  // makes the item visible (logical OR with allowedRoles).
  anyScopes?: string[];
  allowedExportTypes?: ExportRes['type'][];
};

export type StaticNavigationChildItemProps = StaticNavigationBaseItemProps & {
  href: string | (() => string);
};

export type StaticNavigationParentItemProps = StaticNavigationBaseItemProps & {
  children: StaticNavigationItemProps[];
};

export type NavigationItemProps = {
  exportType?: ExportRes['type'];
  role?: User['role'];
  config: StaticNavigationItemProps;
};

export type NavigationProps = {
  exportType?: ExportRes['type'];
  role?: User['role'];
  config: StaticNavigationItemProps[];
};
