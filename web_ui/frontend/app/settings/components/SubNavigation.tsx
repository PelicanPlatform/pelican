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

// SubNavigation is the admin Settings sidebar (General / API /
// Groups / Users / AUP). Most entries are admin-only (the /settings
// layout itself wraps in allowedRoles=['admin']), so when this
// component is dropped on a non-admin-walled page like /groups/
// — where group members are allowed — it would otherwise advertise
// pages the caller can't actually use. Gate it on admin so only
// admins see the sidebar; non-admins on /groups/ get the standard
// chrome without the misleading sub-nav.
const SubNavigation = () => {
  const pathname = usePathname();
  const { data: who } = useSWR('getUser', getUser);
  if (!who?.authenticated || who.role !== 'admin') {
    return null;
  }
  return (
    <Box>
      {NavigationConfiguration.settings.map((item) => (
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
