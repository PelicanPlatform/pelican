'use client';

import {
  cloneElement,
  JSXElementConstructor,
  ReactElement,
  useState,
} from 'react';
import useSWR from 'swr';
import NavigationConfiguration from '@/app/navigation';
import {
  StaticNavigationChildItemProps,
  StaticNavigationParentItemProps,
} from '@/components/layout/Navigation';
import Link from 'next/link';
import { Box, Collapse } from '@mui/material';
import { evaluateOrReturn } from '@/helpers/util';
import { usePathname } from 'next/navigation';
import { getUser } from '@/helpers/login';
import { hasScope } from '@/index';

// SubNavigation is the Settings sidebar (General / API / Groups /
// Users / AUP). Most entries are admin-only; the Users entry is
// reachable by user-admins too (server.user_admin granted directly
// or via group membership). The component renders for any caller
// who has at least one visible item — anyone outside that set sees
// the standard chrome without a misleading sub-nav (e.g. a non-admin
// who landed here from /groups/).
//
// Per-item visibility honors `allowedRoles` and `anyScopes` from the
// nav config: an item is shown if EITHER the role is in
// allowedRoles or any of anyScopes is in the caller's effective
// scope set. An item with neither filter is always visible.
const SubNavigation = () => {
  const pathname = usePathname();
  const { data: who } = useSWR('getUser', getUser);

  if (!who?.authenticated) {
    return null;
  }
  const visibleItems = NavigationConfiguration.settings.filter((item) => {
    if (!item.allowedRoles && !item.anyScopes) return true;
    const roleOk = !!item.allowedRoles && item.allowedRoles.includes(who.role);
    const scopeOk =
      !!item.anyScopes && item.anyScopes.some((s) => hasScope(who, s));
    return roleOk || scopeOk;
  });
  if (visibleItems.length === 0) {
    return null;
  }
  return (
    <Box>
      {visibleItems.map((item) => (
        <NavigationItem
          navItem={item}
          key={evaluateOrReturn(item.title)}
          pathname={pathname}
        />
      ))}
    </Box>
  );
};

const NavigationItem = ({
  navItem,
  pathname,
}: {
  navItem: StaticNavigationParentItemProps | StaticNavigationChildItemProps;
  pathname: string;
}) => {
  if ('children' in navItem) {
    return <NavigationParentItem navItem={navItem} pathname={pathname} />;
  } else {
    return <NavigationChildItem navItem={navItem} pathname={pathname} />;
  }
};

const NavigationChildItem = ({
  navItem,
  pathname,
}: {
  navItem: StaticNavigationChildItemProps;
  pathname: string;
}) => {
  const { title, href, icon } = navItem;
  const linkIsActive = isActive(evaluateOrReturn(href), pathname);

  const iconWithProps = cloneElement(
    icon as ReactElement<any, string | JSXElementConstructor<any>>,
    { fontSize: 'small', color: linkIsActive ? 'primary' : 'inherit' }
  );

  return (
    <Link href={evaluateOrReturn(href)}>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          px: 2,
          py: 1,
          backgroundColor: linkIsActive ? '#f0f0f0' : 'transparent',
          borderRadius: '4px',
          '&:hover': {
            backgroundColor: '#f0f0f0',
          },
        }}
      >
        <Box display={'flex'} alignItems={'center'} justifyContent={'center'}>
          {iconWithProps}
          <Box>
            <span style={{ marginLeft: '8px' }}>{evaluateOrReturn(title)}</span>
          </Box>
        </Box>
      </Box>
    </Link>
  );
};

const NavigationParentItem = ({
  navItem,
  pathname,
}: {
  navItem: StaticNavigationParentItemProps;
  pathname: string;
}) => {
  const { title, icon, children } = navItem;
  const [open, setOpen] = useState(false);

  return (
    <Box>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          p: 0.5,
          borderRadius: '4px',
          cursor: 'pointer',
          '&:hover': { backgroundColor: '#f0f0f0' },
        }}
        onClick={() => setOpen((prev) => !prev)}
      >
        {icon}
        <Box>
          <span style={{ marginLeft: '8px' }}>{evaluateOrReturn(title)}</span>
        </Box>
      </Box>
      <Collapse in={open} timeout='auto' unmountOnExit>
        <Box sx={{ pl: 4 }}>
          {children.map((child) => (
            <NavigationItem
              navItem={child}
              key={evaluateOrReturn(child.title)}
              pathname={pathname}
            />
          ))}
        </Box>
      </Collapse>
    </Box>
  );
};

/**
 * A link is active if its href is the prefix of the current pathname
 * excluding /settings
 * @param href
 * @param pathname
 */
const isActive = (href: string, pathname: string) => {
  // Special case for settings, only match if exactly /settings/
  if (href === '/settings/' && pathname !== '/settings/') return false;

  return pathname.startsWith(href);
};

export default SubNavigation;
