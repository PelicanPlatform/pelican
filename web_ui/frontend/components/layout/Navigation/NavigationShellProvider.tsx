'use client';

import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { usePathname } from 'next/navigation';

import {
  RAIL_LABEL_DISPLAY,
  RAIL_WIDTH,
  RAIL_WIDTH_COLLAPSED,
} from './constants';

type NavigationShell = {
  /**
   * True when a second-level navigation is on screen beside the rail. Set by
   * the sub-navigation itself rather than declared by the layout: the sub-nav
   * hides itself from callers with nothing to see in it, and a rail that
   * shrank for a menu that never appeared would just be a narrower rail.
   */
  subNavigationPresent: boolean;
  setSubNavigationPresent: (present: boolean) => void;
  /** True while the rail has been temporarily revealed from its shrunk state. */
  railExpanded: boolean;
  setRailExpanded: (expanded: boolean) => void;
};

const NavigationShellContext = createContext<NavigationShell>({
  subNavigationPresent: false,
  setSubNavigationPresent: () => {},
  railExpanded: false,
  setRailExpanded: () => {},
});

export const NavigationShellProvider = ({
  children,
}: {
  children: ReactNode;
}) => {
  const [subNavigationPresent, setSubNavigationPresent] = useState(false);
  const [railExpanded, setRailExpanded] = useState(false);
  const pathname = usePathname();

  // Revealing the rail is a temporary act: pick a destination and it folds
  // away again, so two navigations never both claim full width at rest.
  useEffect(() => {
    setRailExpanded(false);
  }, [pathname]);

  const value = useMemo(
    () => ({
      subNavigationPresent,
      setSubNavigationPresent,
      railExpanded,
      setRailExpanded,
    }),
    [subNavigationPresent, railExpanded]
  );

  return (
    <NavigationShellContext.Provider value={value}>
      {children}
    </NavigationShellContext.Provider>
  );
};

export const useNavigationShell = () => useContext(NavigationShellContext);

/**
 * The rail's current geometry.
 *
 * Two stacked navigations cost more horizontal space than the content can
 * spare, so whenever a sub-navigation is present the rail shrinks to its icon
 * width and the sub-navigation offers a way back to it. `collapsed` here means
 * "shrunk regardless of viewport", which is distinct from the rail's ordinary
 * responsive behaviour of being icon-only at medium widths.
 */
export const useRailMetrics = () => {
  const { subNavigationPresent, railExpanded } = useNavigationShell();
  const collapsed = subNavigationPresent && !railExpanded;

  return {
    collapsed,
    // Breakpoint-keyed either way so callers can drop it straight into `sx`.
    // `md` alone is enough when collapsed -- larger breakpoints inherit it.
    width: collapsed ? { md: `${RAIL_WIDTH_COLLAPSED}px` } : RAIL_WIDTH,
    labelDisplay: collapsed ? 'none' : RAIL_LABEL_DISPLAY,
    // Group headings are labels too, so while collapsed the grouping falls
    // back to a rule -- which then has to show at every width, not just md.
    groupDividerDisplay: collapsed
      ? 'block'
      : { md: 'block', lg: 'none' as const },
    // With no labels there is nothing to align a row against, so its contents
    // centre on the icon. These have to track `collapsed` rather than the
    // breakpoint alone, or a shrunk rail on a wide screen would left-align
    // its icons against an edge that is no longer there.
    rowJustify: collapsed
      ? 'center'
      : { md: 'center', lg: 'flex-start' as const },
    iconMargin: collapsed ? 0 : { md: 0, lg: 1.5 },
    logoPadding: collapsed ? 0 : { md: 0, lg: 1 },
  };
};
