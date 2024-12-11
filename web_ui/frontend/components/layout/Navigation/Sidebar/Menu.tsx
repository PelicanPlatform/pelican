'use client';

import React, { ReactNode, useMemo, useRef, useState } from 'react';
import {
  BoxProps,
  IconButton,
  Menu,
  ListItemIcon,
  MenuItem,
  ListItemText,
} from '@mui/material';

import {
  StaticNavigationItemProps,
  StaticNavigationParentItemProps,
} from '@/components/layout/Navigation';
import Link from 'next/link';
import { evaluateOrReturn } from '@/helpers/util';

const NavigationMenu = ({
  config,
}: {
  config: StaticNavigationParentItemProps;
}) => {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  const buttonId = `${config.title}-menu-button`;
  const menuId = `${config.title}-menu`;

  return (
    <>
      <IconButton
        id={buttonId}
        ref={menuRef}
        onClick={() => setOpen(!open)}
        sx={{ mt: 1 }}
      >
        {config.icon}
      </IconButton>
      <Menu
        id={menuId}
        aria-labelledby={buttonId}
        sx={{ ml: 4 }}
        anchorEl={menuRef.current}
        open={open}
        onClose={() => setOpen(false)}
        onClick={() => setOpen(false)}
        anchorOrigin={{
          vertical: 'center',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'center',
          horizontal: 'left',
        }}
      >
        {config.children.map((config) => (
          <NavigationMenuItem
            key={evaluateOrReturn(config.title)}
            config={config}
          />
        ))}
      </Menu>
    </>
  );
};

const NavigationMenuItem = ({
  config,
}: {
  config: StaticNavigationItemProps;
}) => {
  // If this item has children, render a menu
  if ('children' in config) {
    return <NavigationMenu config={config} />;
  }

  // Otherwise, render the navigation item
  return (
    <Link href={evaluateOrReturn(config.href)}>
      <MenuItem>
        <ListItemIcon>{config.icon}</ListItemIcon>
        <ListItemText primary={evaluateOrReturn(config.title)} />
      </MenuItem>
    </Link>
  );
};

export default NavigationMenu;
