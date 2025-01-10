/**
 * Navigation Component for Pelican Sidebar
 */
import { Box, Button, Skeleton, Tooltip } from '@mui/material';
import Link from 'next/link';
import IconButton from '@mui/material/IconButton';
import { Air } from '@mui/icons-material';
import {
  NavigationItemProps,
  StaticNavigationChildItemProps,
  StaticNavigationParentItemProps,
} from '@/components/layout/Navigation';
import { ExportRes } from '@/components/DataExportTable';
import NavigationMenu from '@/components/layout/Navigation/Sidebar/Menu';
import { evaluateOrReturn } from '@/helpers/util';

export const NavigationItem = ({
  exportType,
  role,
  config,
}: NavigationItemProps) => {
  // If the role or export has yet to propogate, show a skeleton
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
    return <NavigationMenu config={config} />;
  }

  // Otherwise, render the navigation item
  return <NavigationChildItem {...config} />;
};

const NavigationChildItem = ({
  title,
  href,
  icon,
  showTitle,
}: StaticNavigationChildItemProps) => {
  return (
    <Box pt={1}>
      <Tooltip title={evaluateOrReturn(title)} placement={'right'}>
        <Link href={evaluateOrReturn(href)}>
          {showTitle ? (
            <Button startIcon={icon}>{evaluateOrReturn(title)}</Button>
          ) : (
            <IconButton>{icon}</IconButton>
          )}
        </Link>
      </Tooltip>
    </Box>
  );
};

const NavigationItemSkeleton = () => {
  return (
    <Skeleton variant='rounded' height={'100%'} width={'100%'}>
      <IconButton>
        <Air />
      </IconButton>
    </Skeleton>
  );
};
