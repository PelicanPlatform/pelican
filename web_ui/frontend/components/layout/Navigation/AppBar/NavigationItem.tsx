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
  Skeleton,
} from '@mui/material';
import Link from 'next/link';
import {
  NavigationItemProps,
  NavigationProps,
  StaticNavigationChildItemProps,
  StaticNavigationItemProps,
  StaticNavigationParentItemProps,
} from '@/components/layout/Navigation';
import { ExportRes } from '@/components/DataExportTable';
import { evaluateOrReturn } from '@/helpers/util';

export const NavigationItem = ({
  exportType,
  role,
  config,
  onClose,
}: { onClose: () => void } & NavigationItemProps) => {
  // If the role or export has yet to propagate, show a skeleton
  if (
    (config?.allowedRoles && role === undefined) ||
    (config?.allowedExportTypes && exportType === undefined)
  ) {
    return <NavigationItemSkeleton />;
  }

  // If the role or export is not allowed, return null
  if (
    (config?.allowedRoles && !config.allowedRoles.includes(role)) ||
    (config?.allowedExportTypes &&
      !config.allowedExportTypes.includes(exportType as ExportRes['type']))
  ) {
    return null;
  }

  // If the item has children, render a menu
  if ('children' in config) {
    return <NavigationMenu config={config} onClose={onClose} />;
  }

  // Otherwise, render the navigation item
  return <NavigationChildItem {...config} onClose={onClose} />;
};

const NavigationChildItem = ({
  title,
  href,
  icon,
  onClose,
}: { onClose: () => void } & StaticNavigationChildItemProps) => {
  return (
    <Link href={evaluateOrReturn(href)} onClick={onClose}>
      <ListItemButton>
        <ListItemIcon>{icon}</ListItemIcon>
        <ListItemText primary={evaluateOrReturn(title)} />
      </ListItemButton>
    </Link>
  );
};

const NavigationItemSkeleton = () => {
  return (
    <Skeleton variant='rounded' height={'100%'} width={'100%'}>
      <ListItem>
        <ListItemText primary={'Loading'} />
      </ListItem>
    </Skeleton>
  );
};

const NavigationMenu = ({
  onClose,
  config,
}: {
  onClose: () => void;
  config: StaticNavigationParentItemProps;
}) => {
  const [open, setOpen] = useState(false);

  return (
    <>
      <ListItemButton
        onClick={() => setOpen(!open)}
        style={{ backgroundColor: open ? '#d1f4ff' : 'inherit' }}
      >
        <ListItemIcon>{config.icon}</ListItemIcon>
        <ListItemText primary={evaluateOrReturn(config.title)} />
      </ListItemButton>
      <Collapse in={open} timeout='auto' unmountOnExit>
        <List component='div' disablePadding>
          <Box pl={1} borderLeft={'#d1f4ff solid 16px'}>
            {config.children.map((config) => (
              <NavigationMenuItem
                key={evaluateOrReturn(config.title)}
                config={config}
                onClose={onClose}
              />
            ))}
          </Box>
        </List>
      </Collapse>
    </>
  );
};

const NavigationMenuItem = ({
  onClose,
  config,
}: {
  onClose: () => void;
  config: StaticNavigationItemProps;
}) => {
  // If this item has children, render a nested menu
  if ('children' in config) {
    return <NavigationMenu config={config} onClose={onClose} />;
  }

  // Otherwise, render the navigation item
  return <NavigationChildItem {...config} onClose={onClose} />;
};
