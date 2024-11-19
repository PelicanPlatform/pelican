import { Avatar, Box, Tooltip } from '@mui/material';
import { FolderOpen, Storage, TripOrigin } from '@mui/icons-material';
import React, { useMemo } from 'react';

const NamespaceIcon = ({
  serverType,
  size,
  color = 'white',
  bgcolor = 'primary.main',
}: {
  serverType: 'origin' | 'cache' | 'namespace';
  size?: 'large' | 'medium' | 'small';
  color?: string;
  bgcolor?: string;
}) => {
  const avatarPixelSize = useMemo(() => {
    switch (size) {
      case 'large':
        return 50;
      case 'medium':
        return 30;
      case 'small':
        return 20;
      default:
        return 30;
    }
  }, [size]);

  const iconPixelSize = useMemo(() => {
    switch (size) {
      case 'large':
        return 30;
      case 'medium':
        return 24;
      case 'small':
        return 15;
      default:
        return 24;
    }
  }, []);

  if (serverType == 'namespace') {
    return (
      <Box>
        <Tooltip title={'Namespace'} placement={'left'}>
          <Avatar
            sizes={'small'}
            sx={{
              height: avatarPixelSize,
              width: avatarPixelSize,
              my: 'auto',
              mr: 1,
              bgcolor,
            }}
          >
            <FolderOpen sx={{ fontSize: iconPixelSize }} htmlColor={color} />
          </Avatar>
        </Tooltip>
      </Box>
    );
  }

  if (serverType == 'origin') {
    return (
      <Box>
        <Tooltip title={'Origin'} placement={'left'}>
          <Avatar
            sizes={'small'}
            sx={{
              height: avatarPixelSize,
              width: avatarPixelSize,
              my: 'auto',
              mr: 1,
              bgcolor,
            }}
          >
            <TripOrigin sx={{ fontSize: iconPixelSize }} htmlColor={color} />
          </Avatar>
        </Tooltip>
      </Box>
    );
  }

  if (serverType == 'cache') {
    return (
      <Box>
        <Tooltip title={'Cache'} placement={'left'}>
          <Avatar
            sizes={'small'}
            sx={{
              height: avatarPixelSize,
              width: avatarPixelSize,
              my: 'auto',
              mr: 1,
              bgcolor,
            }}
          >
            <Storage sx={{ fontSize: iconPixelSize }} htmlColor={color} />
          </Avatar>
        </Tooltip>
      </Box>
    );
  }
};

export default NamespaceIcon;
