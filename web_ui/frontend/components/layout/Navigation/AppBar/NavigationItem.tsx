'use client';

/**
 * AppBar equivalent for the NavigationItem component
 * Uses List component to render the navigation items
 */

import { useState } from 'react';
import {
  Box,
  Collapse,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
} from '@mui/material';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

import {
  NavigationGroupProps,
  NavigationItemProps,
  NavigationViewer,
  NAV_GROUP_SUBHEADER_SX,
  NAV_SELECTED_SX,
  StaticNavigationChildItemProps,
  StaticNavigationItemProps,
  StaticNavigationParentItemProps,
  hasVisibleItem,
  isActive,
  isVisible,
} from '@/components/layout/Navigation';
import { evaluateOrReturn } from '@/helpers/util';

export const NavigationItem = ({
  authenticated,
  exportType,
  role,
  scopes,
  config,
  onClose,
}: { onClose: () => void } & NavigationItemProps) => {
  const viewer: NavigationViewer = { authenticated, role, scopes, exportType };

  return <ResolvedItem config={config} viewer={viewer} onClose={onClose} />;
};

/**
 * Mirrors the rail's grouping so the two surfaces present the same structure.
 * A user who learns the navigation on a laptop and one who learns it on a
 * tablet should end up with the same map of the app.
 */
export const NavigationGroup = ({
  group,
  onClose,
  ...viewer
}: {
  group: NavigationGroupProps;
  onClose: () => void;
} & NavigationViewer) => {
  if (!hasVisibleItem(group, viewer)) {
    return null;
  }

  return (
    <li>
      <ListSubheader
        component={'div'}
        disableSticky
        sx={NAV_GROUP_SUBHEADER_SX}
      >
        {group.group}
      </ListSubheader>
      <List disablePadding aria-label={group.group}>
        {group.items.map((item) => (
          <NavigationItem
            key={evaluateOrReturn(item.title)}
            config={item}
            onClose={onClose}
            {...viewer}
          />
        ))}
      </List>
    </li>
  );
};

type ResolvedItemProps = {
  config: StaticNavigationItemProps;
  viewer: NavigationViewer;
  onClose: () => void;
};

/** An item the caller may or may not be admitted to; absent when they aren't. */
const ResolvedItem = ({ config, viewer, onClose }: ResolvedItemProps) => {
  if (!isVisible(config, viewer)) {
    return null;
  }

  // If the item has children, render a menu
  if ('children' in config) {
    return <NavigationMenu config={config} viewer={viewer} onClose={onClose} />;
  }

  // Otherwise, render the navigation item
  return <NavigationChildItem {...config} onClose={onClose} />;
};

const NavigationChildItem = ({
  title,
  href,
  icon,
  exactMatch,
  onClose,
}: {
  onClose: () => void;
} & StaticNavigationChildItemProps) => {
  const pathname = usePathname();

  const label = evaluateOrReturn(title);
  const path = evaluateOrReturn(href);
  const active = isActive(path, pathname, exactMatch);

  return (
    <ListItem disablePadding>
      <ListItemButton
        component={Link}
        href={path}
        onClick={onClose}
        selected={active}
        aria-current={active ? 'page' : undefined}
        sx={NAV_SELECTED_SX}
      >
        <ListItemIcon sx={{ color: 'inherit' }}>{icon}</ListItemIcon>
        <ListItemText
          primary={label}
          sx={{
            '& .MuiListItemText-primary': {
              fontSize: '1rem',
              fontWeight: active ? 600 : 400,
            },
          }}
        />
      </ListItemButton>
    </ListItem>
  );
};

const NavigationMenu = ({
  config,
  viewer,
  onClose,
}: {
  config: StaticNavigationParentItemProps;
  viewer: NavigationViewer;
  onClose: () => void;
}) => {
  const [open, setOpen] = useState(false);

  const label = evaluateOrReturn(config.title);

  return (
    <li>
      <ListItemButton
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        sx={{ bgcolor: open ? 'action.selected' : 'transparent' }}
      >
        <ListItemIcon>{config.icon}</ListItemIcon>
        <ListItemText primary={label} />
        {open ? <ExpandLess /> : <ExpandMore />}
      </ListItemButton>
      <Collapse in={open} timeout='auto' unmountOnExit>
        <List component='div' disablePadding aria-label={label}>
          <Box sx={{ pl: 1, borderLeft: 16, borderColor: 'primary.light' }}>
            {config.children.map((child) => (
              <ResolvedItem
                key={evaluateOrReturn(child.title)}
                config={child}
                viewer={viewer}
                onClose={onClose}
              />
            ))}
          </Box>
        </List>
      </Collapse>
    </li>
  );
};
