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
} from '@/components/layout/Navigation';
import { ExportRes } from '@/components/DataExportTable';
import NavigationMenu from '@/components/layout/Navigation/Sidebar/Menu';
import { evaluateOrReturn } from '@/helpers/util';

export const NavigationItem = ({
  exportType,
  role,
  config,
}: NavigationItemProps) => {
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
