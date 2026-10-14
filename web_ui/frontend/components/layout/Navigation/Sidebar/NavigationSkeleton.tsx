'use client';

import { Box, Divider, List, ListItem, Skeleton } from '@mui/material';

import {
  NavigationEntry,
  isNavigationGroup,
  useRailMetrics,
} from '@/components/layout/Navigation';
import { evaluateOrReturn } from '@/helpers/util';

/**
 * Stands in for the whole destination list until the server has said who the
 * caller is.
 *
 * It has to be the whole list rather than a skeleton per row: *which* rows
 * survive is precisely what we are waiting to learn, so rendering them
 * optimistically and then deleting the ones this caller may not have would
 * shuffle the rail under the pointer a moment after it looked settled. The
 * placeholder borrows the shape of the configuration -- one row per potential
 * destination, a heading over each group -- so for a caller who can see
 * everything the list it gives way to is the same height, and for everyone
 * else it only ever shortens, never rearranges.
 */
export const NavigationSkeleton = ({
  config,
}: {
  config: NavigationEntry[];
}) => (
  <List disablePadding aria-hidden>
    {config.map((entry) =>
      isNavigationGroup(entry) ? (
        <GroupSkeleton
          key={entry.group}
          label={entry.group}
          rows={entry.items.length}
        />
      ) : (
        <RowSkeleton key={evaluateOrReturn(entry.title)} />
      )
    )}
  </List>
);

/** A single rail row: the pill a RailItemButton draws when it is active. */
const RowSkeleton = () => {
  const { collapsed } = useRailMetrics();

  return (
    <ListItem disablePadding sx={{ display: 'block' }}>
      <Skeleton
        variant={'rounded'}
        height={40}
        sx={{
          my: 0.125,
          borderRadius: 100,
          // Icon-only rows have nothing to stretch to, so the placeholder
          // shrinks to the glyph rather than drawing a pill across a rail
          // that will hold a single icon.
          width: collapsed ? 40 : { md: 40, lg: '100%' },
          mx: collapsed ? 'auto' : { md: 'auto', lg: 0 },
        }}
      />
    </ListItem>
  );
};

/** A named cluster, carried by a rule while the rail is too narrow to label. */
const GroupSkeleton = ({ label, rows }: { label: string; rows: number }) => {
  const { labelDisplay, groupDividerDisplay } = useRailMetrics();

  return (
    <Box component={'li'} sx={{ listStyle: 'none' }}>
      <Divider sx={{ display: groupDividerDisplay, my: 1 }} />
      <Box sx={{ display: labelDisplay, px: 1.5, pt: 1.25 }}>
        <Skeleton
          variant={'text'}
          // Matches the heading's 0.7rem / 1.8 line-height so the rows below
          // start where the real ones will.
          sx={{ fontSize: '0.7rem', lineHeight: 1.8 }}
          width={`${label.length}ch`}
        />
      </Box>
      <List disablePadding>
        {Array.from({ length: rows }, (_, i) => (
          <RowSkeleton key={i} />
        ))}
      </List>
    </Box>
  );
};

export default NavigationSkeleton;
