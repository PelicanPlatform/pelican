'use client';

import React, { useEffect, useRef, useState } from 'react';
import {
  Collapse,
  List,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
} from '@mui/material';
import { ChevronRight, ExpandLess, ExpandMore } from '@mui/icons-material';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

import {
  NavigationViewer,
  StaticNavigationItemProps,
  StaticNavigationParentItemProps,
  isActive,
  isVisible,
  useRailCollapsed,
} from '@/components/layout/Navigation';
import { NavigationChildItem } from '@/components/layout/Navigation/Sidebar/NavigationChildItem';
import RailItemButton from '@/components/layout/Navigation/Sidebar/RailItemButton';
import { evaluateOrReturn } from '@/helpers/util';

/** True when any destination inside this section matches the current route. */
const containsActive = (
  items: StaticNavigationItemProps[],
  pathname: string
): boolean =>
  items.some((item) =>
    'children' in item
      ? containsActive(item.children, pathname)
      : isActive(evaluateOrReturn(item.href), pathname, item.exactMatch)
  );

type NavigationMenuProps = {
  config: StaticNavigationParentItemProps;
  // Children are judged against the same viewer as their parent. Before this
  // they were rendered unconditionally, so a role-gated child under an open
  // parent was shown to everyone.
  viewer: NavigationViewer;
};

const NavigationMenu = ({ config, viewer }: NavigationMenuProps) => {
  const pathname = usePathname();
  const railCollapsed = useRailCollapsed();
  const menuRef = useRef(null);

  const label = evaluateOrReturn(config.title);
  const childActive = containsActive(config.children, pathname);

  // Open when you are already somewhere inside the section, so the rail shows
  // where you are without having to be told. Only the in-place expansion does
  // this: the flyout used while the rail is icon-only is modal, so opening it
  // uninvited would drop a backdrop over the page just navigated to -- and on
  // the first collapsed render its anchor ref is not yet attached, which
  // would leave the menu unanchored at the viewport corner. The flyout opens
  // by click alone, and closes whenever the rail collapses under it.
  const [open, setOpen] = useState(childActive);
  useEffect(() => {
    if (railCollapsed) {
      setOpen(false);
    } else if (childActive) {
      setOpen(true);
    }
  }, [childActive, railCollapsed]);

  const buttonId = `${label}-menu-button`;
  const menuId = `${label}-menu`;

  const children = config.children.filter((child) => isVisible(child, viewer));

  // A rail showing only icons has nowhere to inset labelled children, so the
  // section opens beside it as a flyout rather than expanding in place. This is
  // also why a submenu can't simply be a nested list at every width.
  if (railCollapsed) {
    return (
      <>
        <RailItemButton
          id={buttonId}
          ref={menuRef}
          label={label}
          icon={config.icon}
          onClick={() => setOpen(!open)}
          // Nothing previously distinguished a submenu from a destination:
          // both rendered as a bare icon button, and you found out which you
          // had by clicking it.
          aria-haspopup={'menu'}
          aria-expanded={open}
          aria-controls={open ? menuId : undefined}
          active={childActive}
          trailing={<ChevronRight fontSize={'small'} />}
        />
        <Menu
          id={menuId}
          aria-labelledby={buttonId}
          sx={{ ml: 1 }}
          anchorEl={menuRef.current}
          open={open}
          onClose={() => setOpen(false)}
          onClick={() => setOpen(false)}
          anchorOrigin={{ vertical: 'center', horizontal: 'right' }}
          transformOrigin={{ vertical: 'center', horizontal: 'left' }}
        >
          {children.map((child) => (
            <FlyoutItem
              key={evaluateOrReturn(child.title)}
              config={child}
              viewer={viewer}
              pathname={pathname}
            />
          ))}
        </Menu>
      </>
    );
  }

  return (
    <>
      <RailItemButton
        id={buttonId}
        label={label}
        icon={config.icon}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        // The parent carries the indicator only while the active child is out
        // of sight. Lighting both at once just doubles the highlight.
        active={childActive && !open}
        trailing={
          open ? (
            <ExpandLess fontSize={'small'} />
          ) : (
            <ExpandMore fontSize={'small'} />
          )
        }
      />
      <Collapse in={open} timeout='auto' unmountOnExit>
        <List id={menuId} disablePadding aria-label={label} sx={{ pl: 2 }}>
          {children.map((child) => (
            <NestedItem
              key={evaluateOrReturn(child.title)}
              config={child}
              viewer={viewer}
            />
          ))}
        </List>
      </Collapse>
    </>
  );
};

type ChildProps = {
  config: StaticNavigationItemProps;
  viewer: NavigationViewer;
};

/** A child of an expanded-in-place section: an ordinary rail row, inset. */
const NestedItem = ({ config, viewer }: ChildProps) => {
  if ('children' in config) {
    return <NavigationMenu config={config} viewer={viewer} />;
  }

  return <NavigationChildItem {...config} />;
};

/** A child inside the flyout used while the rail is icon-only. */
const FlyoutItem = ({
  config,
  viewer,
  pathname,
}: ChildProps & { pathname: string }) => {
  if ('children' in config) {
    return <NavigationMenu config={config} viewer={viewer} />;
  }

  const path = evaluateOrReturn(config.href);
  const active = isActive(path, pathname, config.exactMatch);

  return (
    <MenuItem
      component={Link}
      href={path}
      selected={active}
      aria-current={active ? 'page' : undefined}
    >
      <ListItemIcon>{config.icon}</ListItemIcon>
      <ListItemText primary={evaluateOrReturn(config.title)} />
    </MenuItem>
  );
};

export default NavigationMenu;
