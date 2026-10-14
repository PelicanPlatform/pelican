import { ReactNode } from 'react';

import { ExportRes } from '@/components/DataExportTable';
import { ServerType, User } from '@/index';

export type NavigationConfiguration = {
  [key in ServerType | 'shared' | 'settings']: NavigationEntry[];
};

/**
 * A rail is either a bare destination or a named group of them. Grouping is
 * what lets a module exceed the handful of destinations a navigation rail is
 * designed to hold: four labelled clusters of two or three read as four short
 * lists rather than one long one. Only reach for a group when a module has
 * enough destinations to need the structure -- a group of one is ceremony.
 */
export type NavigationEntry = StaticNavigationItemProps | NavigationGroupProps;

export type NavigationGroupProps = {
  group: string;
  items: StaticNavigationItemProps[];
};

export type StaticNavigationItemProps =
  | StaticNavigationParentItemProps
  | StaticNavigationChildItemProps;

export type StaticNavigationBaseItemProps = {
  title: string | (() => string);
  icon: ReactNode;
  allowedRoles?: User['role'][];
  // anyScopes lets a nav item show for callers holding any of these
  // effective scopes, in addition to allowedRoles. Either matching
  // makes the item visible (logical OR with allowedRoles).
  anyScopes?: string[];
  allowedExportTypes?: ExportRes['type'][];
  // requiresLogin marks a destination that admits every signed-in caller and
  // therefore carries no allowedRoles or anyScopes -- a role or scope gate
  // already implies a login (see requiresLogin in navigationVisibility). An
  // anonymous caller does not see the item at all.
  requiresLogin?: boolean;
  // federationOnly hides the item on a server that belongs to no federation
  // (see ServerInfo.standaloneOrigin). Use it for pages whose only consumer is
  // a Director or Registry -- rendering them standalone would offer the admin
  // a control that can never take effect.
  federationOnly?: boolean;
};

export type StaticNavigationChildItemProps = StaticNavigationBaseItemProps & {
  href: string | (() => string);
  // exactMatch limits the active state to this exact pathname. Set it on
  // section roots -- each module's Dashboard, and Settings' own "General"
  // page -- which would otherwise prefix-match every page beneath them and
  // sit permanently lit. See isActive.
  exactMatch?: boolean;
};

export type StaticNavigationParentItemProps = StaticNavigationBaseItemProps & {
  children: StaticNavigationItemProps[];
};

export type NavigationItemProps = {
  // authenticated is undefined until /whoami answers; see NavigationViewer.
  authenticated?: boolean;
  exportType?: ExportRes['type'];
  role?: User['role'];
  // scopes carries the caller's effective scope set so nav items marked
  // with anyScopes can override an otherwise role-based rejection. Empty /
  // undefined means "no scope-based override is possible for this caller".
  scopes?: string[];
  config: StaticNavigationItemProps;
};

export type NavigationProps = {
  authenticated?: boolean;
  exportType?: ExportRes['type'];
  role?: User['role'];
  scopes?: string[];
  config: NavigationEntry[];
  // pending is true while the requests that decide who the caller is are
  // still in flight. The destination list is replaced wholesale by a
  // placeholder for the duration rather than being rendered and then pruned
  // -- see NavigationSkeleton.
  pending?: boolean;
};
