'use client';

import { isValidElement, useEffect, useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Box,
  Collapse,
  Divider,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Skeleton,
  Tab,
  Tabs,
} from '@mui/material';
import { ArrowBack, ExpandLess, ExpandMore } from '@mui/icons-material';

import NavigationConfiguration from '@/app/navigation';
// Imported from the sibling modules rather than the directory barrel: the
// barrel re-exports this component, and going through it would close an
// import cycle.
import type {
  StaticNavigationChildItemProps,
  StaticNavigationItemProps,
  StaticNavigationParentItemProps,
} from '../Navigation.types';
import { NAV_SELECTED_SX } from '../constants';
import { isActive } from '../isActive';
import { isNavigationItem, isVisible } from '../navigationVisibility';
import { useNavigationShell, useRailMetrics } from '../NavigationShellProvider';
import { evaluateOrReturn } from '@/helpers/util';
import { getUser } from '@/helpers/login';

// SubNavigation is the Settings sidebar (General / Config / API / Groups /
// Users / AUP / Logs). Most entries are admin-only; the Users entry is
// reachable by user-admins too (server.user_admin granted directly
// or via group membership). The component renders for any caller
// who has at least one visible item — anyone outside that set sees
// the standard chrome without a misleading sub-nav (e.g. a non-admin
// who landed here from /groups/).
//
// Per-item visibility is the same rule the primary rail applies
// (see navigationVisibility.isVisible), rather than a second copy of it
// here: an item is shown if the caller's role is in `allowedRoles` or they
// hold one of `anyScopes`, and anything behind a login is simply absent for
// an anonymous caller.
//
// Two renderings, switched by CSS rather than a media-query hook so the
// static export and the first client paint agree. From lg up, where the
// settings layout gives it a column beside the content, it is a vertical
// list pinned to the top of the viewport. Below that the content takes the
// full row, so the menu is a horizontal strip of tabs pinned above it: a
// full-height list stacked on top of a narrow page would push the page
// itself below the fold.

// Distance in pixels from the top of the viewport at which the desktop menu
// pins. Equal to PaddedContent's top padding (theme spacing 2), so the menu
// does not jump when it changes from in-flow to stuck.
const STICKY_OFFSET = 16;

/**
 * The destinations as a single flat list, for the tab strip: a strip has no
 * room for disclosure, so a parent's children stand in for it directly.
 */
const flattenItems = (
  items: StaticNavigationItemProps[]
): StaticNavigationChildItemProps[] =>
  items.flatMap((item) =>
    'children' in item ? flattenItems(item.children) : [item]
  );

const SubNavigation = () => {
  const pathname = usePathname();
  const { data: who, error: whoError } = useSWR('getUser', getUser);
  // Resolved rather than loading: an errored /whoami has still answered, and
  // the rules below read an unknown caller as anonymous.
  const whoPending = who === undefined && whoError === undefined;
  const { setSubNavigationPresent, setRailExpanded } = useNavigationShell();
  const { collapsed } = useRailMetrics();

  // The settings shell is a flat list by design — it is short enough not to
  // need the grouping the module rails use — but the config type allows
  // groups, so narrow rather than assume.
  const settingsItems =
    NavigationConfiguration.settings.filter(isNavigationItem);
  const visibleItems = settingsItems.filter((item) =>
    isVisible(item, {
      authenticated: who?.authenticated,
      role: who?.role,
      scopes: who?.scopes,
    })
  );

  // While /whoami is in flight the menu stands as a placeholder rather than
  // being absent. Its presence shrinks the rail and claims a column of the
  // page, so appearing a beat after the page has drawn would move the content
  // the reader is already looking at. A placeholder commits to the layout
  // immediately, and the rows fill in where they will stay.
  const visible =
    whoPending || (!!who?.authenticated && visibleItems.length > 0);

  // Tells the rail to shrink while this menu occupies the column beside it.
  // Computed before the effect so the hook order never depends on the answer.
  useEffect(() => {
    if (!visible) return;
    setSubNavigationPresent(true);
    return () => setSubNavigationPresent(false);
  }, [visible, setSubNavigationPresent]);

  if (!visible) {
    return null;
  }

  const leaves = flattenItems(visibleItems);
  const activeLeaf = leaves.find((item) =>
    isActive(evaluateOrReturn(item.href), pathname, item.exactMatch)
  );

  return (
    <>
      <Box
        sx={{
          display: { xs: 'block', lg: 'none' },
          position: 'sticky',
          top: 0,
          // Above the page content it scrolls over, but well below the
          // burger drawer (1000), which has to be able to cover it.
          zIndex: 1,
          bgcolor: 'background.paper',
          borderBottom: 1,
          borderColor: 'divider',
          // Bleed through PaddedContent's side gutters so no page content
          // peeks out either side of the strip while it is stuck.
          mx: -1,
          px: 1,
        }}
      >
        {whoPending ? (
          <Box sx={{ display: 'flex', gap: 2, minHeight: 44, py: 1 }}>
            {settingsItems.map((item) => (
              <Skeleton
                key={evaluateOrReturn(item.title)}
                variant={'rounded'}
                height={28}
                width={`${evaluateOrReturn(item.title).length + 4}ch`}
              />
            ))}
          </Box>
        ) : (
          <Tabs
            value={activeLeaf ? evaluateOrReturn(activeLeaf.href) : false}
            variant={'scrollable'}
            scrollButtons={'auto'}
            allowScrollButtonsMobile
            aria-label={'Settings'}
            sx={{ minHeight: 44 }}
          >
            {leaves.map((item) => {
              const path = evaluateOrReturn(item.href);
              return (
                <Tab
                  key={path}
                  component={Link}
                  href={path}
                  value={path}
                  label={evaluateOrReturn(item.title)}
                  icon={isValidElement(item.icon) ? item.icon : undefined}
                  iconPosition={'start'}
                  sx={{
                    minHeight: 44,
                    py: 0,
                    textTransform: 'none',
                    fontSize: '0.9rem',
                  }}
                />
              );
            })}
          </Tabs>
        )}
      </Box>
      <List
        disablePadding
        aria-label={'Settings'}
        sx={{
          display: { xs: 'none', lg: 'block' },
          minWidth: 180,
          // Stays put while the page beside it scrolls, so the menu is always
          // in reach on a long settings page. The offset matches the padding
          // PaddedContent puts above it, so it pins exactly where it starts.
          position: 'sticky',
          top: STICKY_OFFSET,
          // Never taller than the viewport it is pinned in: when the menu
          // itself is longer than the page is tall, it scrolls on its own
          // instead of running off the bottom and taking its last entries
          // out of reach.
          maxHeight: `calc(100vh - ${STICKY_OFFSET * 2}px)`,
          overflowY: 'auto',
          scrollbarWidth: 'thin',
        }}
      >
        {collapsed && (
          <>
            <ListItem disablePadding>
              <ListItemButton
                onClick={() => setRailExpanded(true)}
                sx={{ borderRadius: 1, py: 0.75, color: 'text.secondary' }}
              >
                <ListItemIcon sx={{ minWidth: 34, color: 'inherit' }}>
                  <ArrowBack fontSize={'small'} />
                </ListItemIcon>
                <ListItemText
                  primary={'Back'}
                  sx={{
                    '& .MuiListItemText-primary': { fontSize: '0.95rem' },
                  }}
                />
              </ListItemButton>
            </ListItem>
            <Divider sx={{ my: 0.5 }} />
          </>
        )}
        {whoPending
          ? settingsItems.map((item) => (
              <ListItem key={evaluateOrReturn(item.title)} disablePadding>
                <Skeleton
                  variant={'rounded'}
                  height={38}
                  width={'100%'}
                  sx={{ borderRadius: 1 }}
                />
              </ListItem>
            ))
          : visibleItems.map((item) => (
              <NavigationItem
                navItem={item}
                key={evaluateOrReturn(item.title)}
                pathname={pathname}
              />
            ))}
      </List>
    </>
  );
};

const NavigationItem = ({
  navItem,
  pathname,
}: {
  navItem: StaticNavigationItemProps;
  pathname: string;
}) => {
  if ('children' in navItem) {
    return <NavigationParentItem navItem={navItem} pathname={pathname} />;
  }
  return <NavigationChildItem navItem={navItem} pathname={pathname} />;
};

const NavigationChildItem = ({
  navItem,
  pathname,
}: {
  navItem: StaticNavigationChildItemProps;
  pathname: string;
}) => {
  const { title, href, icon, exactMatch } = navItem;

  const path = evaluateOrReturn(href);
  const active = isActive(path, pathname, exactMatch);

  return (
    <ListItem disablePadding>
      <ListItemButton
        component={Link}
        href={path}
        selected={active}
        aria-current={active ? 'page' : undefined}
        sx={{
          borderRadius: 1,
          py: 0.75,
          color: 'text.secondary',
          ...NAV_SELECTED_SX,
        }}
      >
        <ListItemIcon sx={{ minWidth: 34, color: 'inherit' }}>
          {icon}
        </ListItemIcon>
        <ListItemText
          primary={evaluateOrReturn(title)}
          sx={{
            '& .MuiListItemText-primary': {
              fontSize: '0.95rem',
              fontWeight: active ? 600 : 400,
            },
          }}
        />
      </ListItemButton>
    </ListItem>
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

  const label = evaluateOrReturn(title);

  return (
    <li>
      <ListItemButton
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        sx={{ borderRadius: 1, py: 0.75 }}
      >
        <ListItemIcon sx={{ minWidth: 34 }}>{icon}</ListItemIcon>
        <ListItemText
          primary={label}
          sx={{ '& .MuiListItemText-primary': { fontSize: '0.95rem' } }}
        />
        {open ? (
          <ExpandLess fontSize={'small'} />
        ) : (
          <ExpandMore fontSize={'small'} />
        )}
      </ListItemButton>
      <Collapse in={open} timeout='auto' unmountOnExit>
        <List disablePadding sx={{ pl: 2 }} aria-label={label}>
          {children.map((child) => (
            <NavigationItem
              navItem={child}
              key={evaluateOrReturn(child.title)}
              pathname={pathname}
            />
          ))}
        </List>
      </Collapse>
    </li>
  );
};

export default SubNavigation;
