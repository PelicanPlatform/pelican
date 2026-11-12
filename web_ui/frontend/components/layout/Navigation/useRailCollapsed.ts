'use client';

import { useMediaQuery, useTheme } from '@mui/material';

import { useRailMetrics } from './NavigationShellProvider';

/**
 * True while the rail is showing icons without labels -- either because the
 * viewport is too narrow for them, or because a sub-navigation is on screen
 * and the rail has shrunk to make room for it.
 *
 * Rail items keep a tooltip so a collapsed icon still has a name, but once the
 * label is visible that tooltip only repeats what is already on screen and
 * covers the content beside it. This tells an item which of the two it is.
 *
 * The viewport half of the answer reports false on first render, matching the
 * statically exported HTML, and corrects itself on hydration. Nothing about
 * the layout depends on it -- only whether a hover reveals a tooltip -- so
 * there is no visible shift.
 */
export const useRailCollapsed = (): boolean => {
  const theme = useTheme();
  const narrowViewport = useMediaQuery(theme.breakpoints.down('lg'));
  const { collapsed } = useRailMetrics();

  return collapsed || narrowViewport;
};
