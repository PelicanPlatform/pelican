import React, { useState } from 'react';
import {
  List,
  ListItem,
  ListItemText,
  Collapse,
  IconButton,
  Box,
} from '@mui/material';
import {
  Api,
  BugReport,
  Description,
  GitHub,
  HelpOutline,
} from '@mui/icons-material';
import {
  NavigationItemProps,
  NavigationProps,
  StaticNavigationBaseItemProps,
  StaticNavigationItemProps,
} from '@/components/layout/Navigation/index';
import Container from '@mui/material/Container';
import Toolbar from '@mui/material/Toolbar';
import Image from 'next/image';
import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';
import Typography from '@mui/material/Typography';
import UserMenu from '@/components/layout/Navigation/Sidebar/UserMenu';
import AppBar from '@mui/material/AppBar';
import { Close } from '@mui/icons-material';
import { NavigationItem } from '@/components/layout/Navigation/AppBar/NavigationItem';
import { getVersionNumber } from '@/components/layout/Navigation/Sidebar/AboutMenu';

const helpMenu: StaticNavigationItemProps[] = [
  {
    icon: <HelpOutline />,
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

const BurgerMenu: React.FC<BurgerMenuProps> = ({
  config,
  exportType,
  role,
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
              href='#app-bar-with-responsive-menu'
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
      <List component='nav'>
        {[...config, ...helpMenu].map((item, index) => (
          <NavigationItem
            key={index}
            config={item}
            role={role}
            exportType={exportType}
            onClose={onClose}
          />
        ))}
      </List>
    </Box>
  );
};

export default BurgerMenu;
