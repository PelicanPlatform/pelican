/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import React from 'react';
import {
  Box,
  ClickAwayListener,
  Divider,
  Drawer,
  List,
  ListSubheader,
} from '@mui/material';
import Image from 'next/image';
import { default as NextLink } from 'next/link';

import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';
import { evaluateOrReturn } from '@/helpers/util';
import {
  NavigationGroupProps,
  NavigationProps,
  NavigationViewer,
  hasVisibleItem,
  isNavigationGroup,
  useNavigationShell,
  useRailMetrics,
} from '@/components/layout/Navigation';
import { NavigationItem } from '@/components/layout/Navigation/Sidebar/NavigationItem';
import NavigationSkeleton from '@/components/layout/Navigation/Sidebar/NavigationSkeleton';
import UserMenu from './UserMenu';
import AboutMenu from './AboutMenu';

export const Sidebar = ({
  config,
  authenticated,
  exportType,
  role,
  scopes,
  pending,
}: NavigationProps) => {
  const viewer: NavigationViewer = { authenticated, role, scopes, exportType };
  const { width, rowJustify, logoPadding } = useRailMetrics();
  const { railExpanded, setRailExpanded } = useNavigationShell();

  const drawer = (
    <Drawer
      variant='permanent'
      anchor='left'
      sx={{
        width,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width,
          transition: (theme) =>
            theme.transitions.create('width', {
              duration: theme.transitions.duration.shorter,
            }),
          boxSizing: 'border-box',
          // Keep the low z-index the hand-rolled sidebar used rather than
          // MUI's drawer layer so page content and dialogs stack as before.
          zIndex: 2,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          px: 1,
          py: 2,
          // The destination list scrolls on its own (below); the paper itself
          // must not, or the user menu at the foot scrolls away with it.
          overflow: 'hidden',
          borderRight: 1,
          borderColor: 'divider',
        },
      }}
      slotProps={{
        // Gives the rail a real navigation landmark, which the previous
        // fixed-position Box could not offer.
        paper: { component: 'nav', 'aria-label': 'Primary' },
      }}
    >
      <Box sx={{ minHeight: 0, overflowY: 'auto', overflowX: 'hidden' }}>
        <Box
          sx={{
            display: 'flex',
            justifyContent: rowJustify,
            px: logoPadding,
            pb: 1.5,
          }}
        >
          <NextLink href={'/'} aria-label={'Pelican home'}>
            <Image
              src={PelicanLogo}
              alt={'Pelican Logo'}
              width={36}
              height={36}
              priority={true}
              loading={'eager'}
            />
          </NextLink>
        </Box>
        {pending ? (
          <NavigationSkeleton config={config} />
        ) : (
          <List disablePadding>
            {config.map((entry) =>
              isNavigationGroup(entry) ? (
                <NavigationGroup key={entry.group} group={entry} {...viewer} />
              ) : (
                <NavigationItem
                  key={evaluateOrReturn(entry.title)}
                  config={entry}
                  {...viewer}
                />
              )
            )}
          </List>
        )}
      </Box>
      {/*
        Account and help are rail rows like everything above them, not free
        floating circles: same height, same left alignment, same tooltip
        behaviour when collapsed. The rule separates them from the
        destinations without changing their shape.
      */}
      <Box>
        <Divider sx={{ mx: 1, mb: 0.5 }} />
        <List disablePadding>
          <UserMenu variant={'rail'} />
          <AboutMenu />
        </List>
      </Box>
    </Drawer>
  );

  if (!railExpanded) {
    return drawer;
  }

  // A revealed rail folds away again as soon as attention moves elsewhere, so
  // it never quietly keeps the width it borrowed. The listener is mounted only
  // while the rail is open: the click that opens it comes from the "Back"
  // control in the sub-navigation, which is outside the drawer and would
  // otherwise be treated as a click away, closing it in the same gesture.
  return (
    <ClickAwayListener onClickAway={() => setRailExpanded(false)}>
      {drawer}
    </ClickAwayListener>
  );
};

/**
 * A named cluster of destinations. While the rail is collapsed there is no
 * room for the heading, so the grouping is carried by a rule instead -- the
 * structure survives even when the labels can't.
 */
const NavigationGroup = ({
  group,
  ...viewer
}: { group: NavigationGroupProps } & NavigationViewer) => {
  const { labelDisplay, groupDividerDisplay } = useRailMetrics();

  if (!hasVisibleItem(group, viewer)) {
    return null;
  }

  return (
    <Box component={'li'} sx={{ listStyle: 'none' }}>
      <Divider sx={{ display: groupDividerDisplay, my: 1 }} />
      <ListSubheader
        disableSticky
        // Rendered as a div: the group already sits inside an <li>, and
        // ListSubheader would otherwise nest a second one inside it.
        component={'div'}
        sx={{
          display: labelDisplay,
          bgcolor: 'transparent',
          color: 'text.secondary',
          fontSize: '0.7rem',
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          lineHeight: 1.8,
          px: 1.5,
          pt: 1.25,
        }}
      >
        {group.group}
      </ListSubheader>
      <List disablePadding aria-label={group.group}>
        {group.items.map((item) => (
          <NavigationItem
            key={evaluateOrReturn(item.title)}
            config={item}
            {...viewer}
          />
        ))}
      </List>
    </Box>
  );
};

export default Sidebar;
