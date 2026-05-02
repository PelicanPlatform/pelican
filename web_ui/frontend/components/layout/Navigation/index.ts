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
  // topOffset (px) is the vertical space reserved above the navigation
  // by an out-of-flow banner sitting at the top of the viewport (e.g.
  // the admin-session banner). The sidebar's fixed positioning ignores
  // its parent's padding, so the offset has to be threaded down to the
  // sidebar/appbar themselves and applied to their own `top` /
  // `height: calc(100vh - <offset>)` rules.
  topOffset?: number;
};
