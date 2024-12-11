import * as React from 'react';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Menu from '@mui/material/Menu';
import MenuIcon from '@mui/icons-material/Menu';
import Container from '@mui/material/Container';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import MenuItem from '@mui/material/MenuItem';
import AdbIcon from '@mui/icons-material/Adb';
import { NavigationProps } from '@/components/layout/Navigation';
import Image from 'next/image';
import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';
import styles from '@/app/page.module.css';
import UserMenu from '@/components/layout/Navigation/Sidebar/UserMenu';
import { Collapse, Drawer } from '@mui/material';
import BurgerMenu from '@/components/layout/Navigation/AppBar/BurgerMenu';

const pages = ['Products', 'Pricing', 'Blog'];
const settings = ['Profile', 'Account', 'Dashboard', 'Logout'];

function ResponsiveAppBar({ config, exportType, role }: NavigationProps) {
  const [navOpen, setNavOpen] = React.useState(false);

  return (
    <>
      <AppBar
        position='static'
        sx={{
          background:
            'conic-gradient(from 180deg at 101% 100%, #54d6ff 0deg, #0885ff 55deg, #54d6ff 120deg, #54d6ff 160deg, #0071ff 360deg)',
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
                onClick={() => setNavOpen(!navOpen)}
              >
                <MenuIcon />
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
      <Box
        sx={{
          position: 'fixed',
          top: 0,
          width: '100vw',
          backgroundColor: 'white',
          zIndex: 1000,
        }}
      >
        <Collapse in={navOpen}>
          <BurgerMenu
            config={config}
            exportType={exportType}
            role={role}
            onClose={() => setNavOpen(false)}
          />
        </Collapse>
      </Box>
    </>
  );
}
export default ResponsiveAppBar;
