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
  // Hard rejections first: when role or exportType are known and don't
  // match, hide the item without ever showing the loading skeleton.
  // Order matters — non-admins never load exportType (the upstream
  // /origin_ui/exports fetch is skipped for them), so a role-based
  // rejection has to be able to short-circuit before the exportType
  // skeleton branch below would otherwise sit forever.
  if (
    config?.allowedRoles &&
    role !== undefined &&
    !config.allowedRoles.includes(role)
  ) {
    return null;
  }
  if (
    config?.allowedExportTypes &&
    exportType !== undefined &&
    !config.allowedExportTypes.includes(exportType as ExportRes['type'])
  ) {
    return null;
  }

  // Still waiting on data we'd need to make a final decision.
  if (
    (config?.allowedRoles && role === undefined) ||
    (config?.allowedExportTypes && exportType === undefined)
  ) {
    return <NavigationItemSkeleton />;
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
