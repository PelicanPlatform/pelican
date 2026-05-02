'use client';

import useSWR from 'swr';
import { useRouter } from 'next/navigation';
import React, { useState } from 'react';
import {
  Box,
  Divider,
  IconButton,
  Menu,
  MenuItem,
  MenuProps,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  AccountCircle,
  AdminPanelSettings,
  CloudSync,
  Login,
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
        {/*
          Identity header. Two stacked lines so a long display name +
          username pair doesn't blow out the menu's width:
            line 1 — display name (or username when none is set)
            line 2 — the literal username, monospaced and dimmed
                     (suppressed when it would just repeat line 1)
          Followed by a small role tag so the admin-vs-user signal we
          used to convey via "Admin User" / "User" doesn't disappear.
        */}
        <Box sx={{ px: 2, py: 1, maxWidth: 240 }}>
          <Typography
            variant='body2'
            sx={{ fontWeight: 600, wordBreak: 'break-word' }}
          >
            {user.displayName || user.user || 'Unknown user'}
          </Typography>
          {user.displayName && user.user && user.displayName !== user.user && (
            <Typography
              variant='caption'
              color='text.secondary'
              sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
            >
              {user.user}
            </Typography>
          )}
          <Typography
            variant='caption'
            color='text.secondary'
            sx={{ display: 'block', mt: 0.25 }}
          >
            {user.role === 'admin' ? 'Administrator' : 'User'}
          </Typography>
        </Box>
        <Divider />
        <MenuItem
          onClick={() => {
            setMenuOpen(false);
            router.push('/profile/');
          }}
        >
          Profile
        </MenuItem>
        <MenuItem onClick={handleLogout}>Logout</MenuItem>
      </Menu>
      {error && <StatusSnackBar message={error} severity={'error'} />}
    </>
  );
};

export default UserMenu;
