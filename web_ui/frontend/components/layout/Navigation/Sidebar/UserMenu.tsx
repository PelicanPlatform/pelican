'use client';

import useSWR from 'swr';
import { useRouter } from 'next/navigation';
import React, { useContext, useState } from 'react';
import { IconButton, Menu, MenuItem, MenuProps, Tooltip } from '@mui/material';
import {
  Login,
  AccountCircle,
  CloudSync,
  AdminPanelSettings,
} from '@mui/icons-material';
import StatusSnackBar from '@/components/StatusSnackBar';
import { getUser } from '@/helpers/login';
import { getErrorMessage } from '@/helpers/util';

const UserMenu = ({ menuOptions }: { menuOptions?: Partial<MenuProps> }) => {
  const userMenuRef = React.useRef(null);

  const {
    data: user,
    isLoading,
    error: fetchError,
    mutate,
  } = useSWR('getUser', getUser, {
    refreshInterval: 1000 * 60,
    fallbackData: { authenticated: false },
  });

  const router = useRouter();

  const [menuOpen, setMenuOpen] = useState(false);
  const [error, setError] = useState<string | undefined>(undefined);

  const handleLogout = async (e: React.MouseEvent<HTMLElement>) => {
    try {
      let response = await fetch('/api/v1.0/auth/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        await mutate(getUser);
      } else {
        setError(await getErrorMessage(response));
      }
    } catch {
      setError('Could not connect to server');
    }
  };

  if (isLoading) {
    return (
      <IconButton>
        <CloudSync />
      </IconButton>
    );
  }

  if (!user.authenticated) {
    return (
      <Tooltip title={'Login'} placement={'right'}>
        <IconButton
          id={'user-menu-button'}
          ref={userMenuRef}
          sx={{
            bgcolor: '#767adb4a',
          }}
          onClick={() =>
            router.push('/login' + '?returnURL=' + window.location.pathname)
          }
        >
          <Login />
        </IconButton>
      </Tooltip>
    );
  }

  return (
    <>
      <IconButton
        id={'user-menu-button'}
        ref={userMenuRef}
        sx={{
          bgcolor: '#4dba5a3b',
        }}
        onClick={() => setMenuOpen(!menuOpen)}
      >
        {user.role === 'admin' ? <AdminPanelSettings /> : <AccountCircle />}
      </IconButton>
      <Menu
        id={'user-menu'}
        aria-labelledby={'user-menu-button'}
        sx={{ ml: 4 }}
        anchorEl={userMenuRef.current}
        open={menuOpen}
        onClose={() => setMenuOpen(false)}
        anchorOrigin={{
          vertical: 'center',
          horizontal: 'right',
          ...menuOptions?.anchorOrigin,
        }}
        transformOrigin={{
          vertical: 'center',
          horizontal: 'left',
          ...menuOptions?.transformOrigin,
        }}
        {...menuOptions}
      >
        {user.role === 'admin' ? (
          <MenuItem disabled={true}>Admin User</MenuItem>
        ) : null}
        {user.role !== 'admin' ? (
          <MenuItem disabled={true}>User</MenuItem>
        ) : null}
        <MenuItem onClick={handleLogout}>Logout</MenuItem>
      </Menu>
      {error && <StatusSnackBar message={error} severity={'error'} />}
    </>
  );
};

export default UserMenu;
