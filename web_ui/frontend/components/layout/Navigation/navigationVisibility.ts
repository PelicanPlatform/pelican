import { ExportRes } from '@/components/DataExportTable';
import { User } from '@/index';

import {
  NavigationEntry,
  NavigationGroupProps,
  StaticNavigationItemProps,
} from './Navigation.types';

export type NavigationViewer = {
  // Every field here is undefined until the request that supplies it has
  // answered. Nothing below treats that as a third state: the navigation
  // shell holds a placeholder until the whole viewer is known (see
  // Navigation), so by the time these functions run the answers are in and an
  // undefined field means "the caller genuinely has none".
  authenticated?: boolean;
  role?: User['role'];
  scopes?: string[];
  exportType?: ExportRes['type'];
};

// hasAnyMatchingScope returns true when the caller holds at least one of the
// scopes an item lists in its anyScopes. Undefined on either side means "no
// scope-based admittance", so we return false and let the role check decide.
const hasAnyMatchingScope = (
  itemScopes: string[] | undefined,
  userScopes: string[] | undefined
): boolean => {
  if (!itemScopes || !userScopes) return false;
  return itemScopes.some((s) => userScopes.includes(s));
};

/**
 * True when an anonymous caller cannot see the destination.
 *
 * Derived rather than declared wherever possible: any role or scope gate
 * implies a login, so an item can't be marked admin-only and forget to also
 * say it needs a login. The explicit `requiresLogin` flag is for the pages
 * that admit every signed-in user and therefore carry no role at all.
 */
export const requiresLogin = (item: StaticNavigationItemProps): boolean =>
  !!item.requiresLogin || !!item.allowedRoles || !!item.anyScopes;

/**
 * Decides whether a caller may see a navigation item.
 *
 * The navigation shows where you can go, not where you can't: a destination
 * the caller cannot reach is absent, never present-but-marked. A padlocked
 * row only offers a door that closes on you, and it leaks the shape of the
 * admin surface to anonymous callers besides.
 *
 * This lives on its own because the rail and the burger menu both need it and
 * previously held their own copies -- a scope bug had to be found and fixed
 * twice, in two files that had already drifted apart in their comments.
 */
export const isVisible = (
  item: StaticNavigationItemProps,
  viewer: NavigationViewer
): boolean => {
  const { authenticated, role, scopes, exportType } = viewer;

  if (!authenticated && requiresLogin(item)) {
    return false;
  }

  // anyScopes: an item that admits scope holders in addition to a role
  // (e.g. the log viewer is reachable via server.admin OR pelican.log_read)
  // must NOT be hidden by a bare role mismatch when the caller does hold
  // one of the listed scopes. Match the AuthenticatedContent gate so a
  // user who can visit the page can also see it in the navigation.
  if (
    item.allowedRoles &&
    !item.allowedRoles.includes(role) &&
    !hasAnyMatchingScope(item.anyScopes, scopes)
  ) {
    return false;
  }

  // An unknown export type hides the item rather than showing it. The
  // /origin_ui/exports fetch is admin-only and may fail outright, and an
  // export-conditional entry would otherwise promise a page that does not
  // exist on this server.
  if (
    item.allowedExportTypes &&
    !(exportType && item.allowedExportTypes.includes(exportType))
  ) {
    return false;
  }

  // A section is worth no more than its contents: a parent whose every child
  // is out of reach would open onto nothing.
  if ('children' in item) {
    return item.children.some((child) => isVisible(child, viewer));
  }

  return true;
};

export const isNavigationGroup = (
  entry: NavigationEntry
): entry is NavigationGroupProps => 'group' in entry;

export const isNavigationItem = (
  entry: NavigationEntry
): entry is StaticNavigationItemProps => !isNavigationGroup(entry);

/**
 * Drops groups whose every item is hidden from this caller, so a scope-limited
 * user never sees a section heading standing over nothing.
 */
export const hasVisibleItem = (
  group: NavigationGroupProps,
  viewer: NavigationViewer
): boolean => group.items.some((item) => isVisible(item, viewer));
