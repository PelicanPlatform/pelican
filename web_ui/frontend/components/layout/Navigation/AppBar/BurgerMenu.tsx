import React from 'react';
import { Box, IconButton, List, ListItem, Skeleton } from '@mui/material';
import {
  Api,
  BugReport,
  Close,
  Description,
  GitHub,
  Help,
} from '@mui/icons-material';
import {
  NavigationEntry,
  NavigationProps,
  isNavigationGroup,
} from '@/components/layout/Navigation/index';
import { evaluateOrReturn } from '@/helpers/util';
import Container from '@mui/material/Container';
import Toolbar from '@mui/material/Toolbar';
import Image from 'next/image';
import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';
import Typography from '@mui/material/Typography';
import UserMenu from '@/components/layout/Navigation/Sidebar/UserMenu';
import AppBar from '@mui/material/AppBar';
import {
  NavigationGroup,
  NavigationItem,
} from '@/components/layout/Navigation/AppBar/NavigationItem';
import { getVersionNumber } from '@/components/layout/Navigation/Sidebar/AboutMenu';

const helpMenu: NavigationEntry[] = [
  {
    icon: <Help />,
    title: 'Help',
    children: [
      {
        icon: <Description />,
        title: 'Documentation',
        href: 'https://docs.pelicanplatform.org',
      },
      {
        icon: <Api />,
        title: 'Pelican Server API',
        href: '/api/v1.0/docs',
      },
      {
        icon: <GitHub />,
        title: () => `Release ${getVersionNumber()}`,
        href: () =>
          `https://github.com/PelicanPlatform/pelican/releases/tag/v${getVersionNumber()}`,
      },
      {
        icon: <BugReport />,
        title: 'Report Bug',
        href: 'https://github.com/PelicanPlatform/pelican/issues/new',
      },
    ],
  },
];

type BurgerMenuProps = { onClose: () => void } & NavigationProps;

/**
 * Stands in for the destination list while we are still learning who the
 * caller is -- the burger menu's half of the rail's placeholder, for the same
 * reason: the rows that survive are exactly what is being waited on, so none
 * are drawn until they are all known. See Sidebar/NavigationSkeleton.
 */
const MenuSkeleton = ({ rows }: { rows: number }) => (
  <List aria-hidden>
    {Array.from({ length: rows }, (_, i) => (
      <ListItem key={i}>
        <Skeleton variant={'rounded'} height={24} width={'100%'} />
      </ListItem>
    ))}
  </List>
);

/** One row per potential destination, groups contributing their contents. */
const countRows = (entries: NavigationEntry[]): number =>
  entries.reduce(
    (total, entry) =>
      total + (isNavigationGroup(entry) ? entry.items.length : 1),
    0
  );

const BurgerMenu: React.FC<BurgerMenuProps> = ({
  config,
  authenticated,
  exportType,
  role,
  scopes,
  pending,
  onClose,
}) => {
  return (
    <Box sx={{ height: '100vh' }}>
      <AppBar
        position='static'
        sx={{
          background:
            'conic-gradient(from 180deg at 101% 100%, #d1f4ff 0deg, #d1f4ff 55deg, #d1f4ff 120deg, #d1f4ff 160deg, #d8f0f8 360deg)',
          boxShadow: 'none',
        }}
      >
        <Container maxWidth='xl'>
          <Toolbar disableGutters>
            <Box sx={{ flexGrow: 1, display: { xs: 'flex', md: 'none' } }}>
              <IconButton
                size='large'
                aria-label='account of current user'
                aria-controls='menu-appbar'
                aria-haspopup='true'
                onClick={onClose}
              >
                <Close />
              </IconButton>
            </Box>
            <Image
              src={PelicanLogo}
              alt={'Pelican Logo'}
              width={36}
              height={36}
              priority={true}
              loading={'eager'}
            />
            <Typography
              variant='h6'
              noWrap
              component='a'
              href='/'
              sx={{
                m: 2,
                display: { xs: 'flex', md: 'none' },
                flexGrow: 1,
                lineHeight: '1.2',
                letterSpacing: '.3rem',
                textDecoration: 'none',
                color: 'black',
              }}
            >
              Pelican
              <br />
              Platform
            </Typography>
            <Box sx={{ flexGrow: 0 }}>
              <UserMenu
                menuOptions={{
                  anchorOrigin: {
                    vertical: 'bottom',
                    horizontal: 'left',
                  },
                  transformOrigin: {
                    vertical: 'top',
                    horizontal: 'right',
                  },
                }}
              />
            </Box>
          </Toolbar>
        </Container>
      </AppBar>
      {pending ? (
        <MenuSkeleton rows={countRows([...config, ...helpMenu])} />
      ) : (
        <List component='nav' aria-label={'Primary'}>
          {[...config, ...helpMenu].map((entry) =>
            isNavigationGroup(entry) ? (
              <NavigationGroup
                key={entry.group}
                group={entry}
                authenticated={authenticated}
                role={role}
                scopes={scopes}
                exportType={exportType}
                onClose={onClose}
              />
            ) : (
              <NavigationItem
                key={evaluateOrReturn(entry.title)}
                config={entry}
                authenticated={authenticated}
                role={role}
                scopes={scopes}
                exportType={exportType}
                onClose={onClose}
              />
            )
          )}
        </List>
      )}
    </Box>
  );
};

export default BurgerMenu;
