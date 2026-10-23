'use client';

import { forwardRef, ReactNode } from 'react';
import {
  Box,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Tooltip,
} from '@mui/material';
import Link from 'next/link';

import {
  NAV_SELECTED_SX,
  useRailMetrics,
  useRailCollapsed,
} from '@/components/layout/Navigation';

export type RailItemButtonProps = {
  label: string;
  icon: ReactNode;
  /** Navigates when set; otherwise the row is a button (submenu, account, help). */
  href?: string;
  /** Marks the current page, drawing Material's active indicator. */
  active?: boolean;
  /** Shown at the end of the row while the rail is expanded, e.g. a disclosure chevron. */
  trailing?: ReactNode;
  id?: string;
  onClick?: () => void;
  'aria-haspopup'?: 'menu';
  'aria-expanded'?: boolean;
  'aria-controls'?: string;
};

/**
 * One row of the navigation rail.
 *
 * Destinations, submenu triggers, and the account and help controls at the
 * foot of the rail are all the same kind of thing to someone reading it -- a
 * target with an icon and a name -- so they share a single row: same height,
 * same alignment, same active treatment. The account and help controls were
 * previously bare centred circles, which read as leftover chrome beside a
 * column of labelled rows.
 */
export const RailItemButton = forwardRef<HTMLDivElement, RailItemButtonProps>(
  function RailItemButton(
    { label, icon, href, active, trailing, ...props },
    ref
  ) {
    const railCollapsed = useRailCollapsed();
    const { labelDisplay, rowJustify, iconMargin } = useRailMetrics();

    const content = (
      <>
        <ListItemIcon
          sx={{
            minWidth: 0,
            mr: iconMargin,
            justifyContent: 'center',
            // Inherit so the icon travels with the row's active colour rather
            // than sitting at MUI's default action grey.
            color: 'inherit',
          }}
        >
          {icon}
        </ListItemIcon>
        <ListItemText
          primary={label}
          sx={{
            display: labelDisplay,
            my: 0,
            // Size and weight go through a descendant selector rather than
            // slotProps: the label renders as a body1 Typography and this
            // theme sets body1 to 1.2rem, which a single-class rule on the
            // slot does not reliably outrank.
            '& .MuiListItemText-primary': {
              fontSize: '0.9rem',
              fontWeight: active ? 600 : 500,
            },
          }}
          slotProps={{ primary: { noWrap: true } }}
        />
        {trailing && (
          <Box sx={{ display: labelDisplay, lineHeight: 0, opacity: 0.6 }}>
            {trailing}
          </Box>
        )}
      </>
    );

    const buttonProps = {
      selected: active,
      // The pill alone doesn't reach assistive technology, and the rail
      // previously offered no current-page signal at all.
      'aria-current': active ? ('page' as const) : undefined,
      sx: {
        minHeight: 40,
        my: 0.125,
        px: 1.5,
        justifyContent: rowJustify,
        // A fully rounded container is what marks the active destination in
        // Material's navigation rail.
        borderRadius: 100,
        color: 'text.secondary',
        ...NAV_SELECTED_SX,
      },
      ...props,
    };

    return (
      <ListItem disablePadding sx={{ display: 'block' }}>
        {/*
          The tooltip names the destination while the rail is collapsed. Once
          the label is visible it would only repeat it, over the top of the
          content beside the rail, so it stands down.
        */}
        <Tooltip
          title={label}
          placement={'right'}
          disableHoverListener={!railCollapsed}
          disableFocusListener={!railCollapsed}
          disableTouchListener={!railCollapsed}
        >
          {href ? (
            <ListItemButton component={Link} href={href} {...buttonProps}>
              {content}
            </ListItemButton>
          ) : (
            <ListItemButton ref={ref} {...buttonProps}>
              {content}
            </ListItemButton>
          )}
        </Tooltip>
      </ListItem>
    );
  }
);

export default RailItemButton;
