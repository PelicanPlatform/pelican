'use client';

/**
 * Navigation Component for Pelican Sidebar
 */
import {
  NavigationItemProps,
  NavigationViewer,
  isVisible,
} from '@/components/layout/Navigation';
import NavigationMenu from '@/components/layout/Navigation/Sidebar/Menu';
import { NavigationChildItem } from '@/components/layout/Navigation/Sidebar/NavigationChildItem';

export const NavigationItem = ({
  authenticated,
  exportType,
  role,
  scopes,
  config,
}: NavigationItemProps) => {
  const viewer: NavigationViewer = { authenticated, role, scopes, exportType };

  if (!isVisible(config, viewer)) {
    return null;
  }

  // If the item has children, render a menu
  if ('children' in config) {
    return <NavigationMenu config={config} viewer={viewer} />;
  }

  // Otherwise, render the navigation item
  return <NavigationChildItem {...config} />;
};
