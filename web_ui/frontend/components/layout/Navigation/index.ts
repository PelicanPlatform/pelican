import { ServerType, User } from '@/index';
import { ReactNode } from 'react';
export { Navigation } from './Navigation';
import { ExportRes } from '@/components/DataExportTable';

export type NavigationConfiguration = {
  [key in ServerType | 'shared']: StaticNavigationItemProps[];
};

export type StaticNavigationItemProps =
  | StaticNavigationParentItemProps
  | StaticNavigationChildItemProps;

export type StaticNavigationBaseItemProps = {
  title: string | (() => string);
  icon: ReactNode;
  showTitle?: boolean;
  allowedRoles?: User['role'][];
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
