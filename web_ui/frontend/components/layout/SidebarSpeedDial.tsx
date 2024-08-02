'use client';

import React, { ReactNode, useState } from 'react';
import { Add } from '@mui/icons-material';
import {
  Box,
  BoxProps,
  Button,
  Grow,
  IconButton,
  Paper,
  Tooltip,
} from '@mui/material';
import Link from 'next/link';
import { ClickAwayListener } from '@mui/base';

interface SpeedButtonProps {
  boxProps?: BoxProps;
  href?: string;
  icon: ReactNode;
  newTab?: boolean;
  onClick?: () => void;
  open: boolean;
  order: number;
  text?: string;
  title: string;
}

export const getVersionNumber = () => {
  const { version } = require('../../package.json');
  return version;
};

const SpeedDialButton = ({
  open,
  order,
  text,
  icon,
  title,
  onClick,
  href,
  newTab,
  boxProps,
}: SpeedButtonProps) => {
  let button = <></>;
  if (text) {
    button = (
      <Button
        variant='outlined'
        sx={{ bgcolor: 'white', '&:hover': { bgcolor: 'white' } }}
        startIcon={icon}
        onClick={onClick}
      >
        {text}
      </Button>
    );
  } else {
    button = (
      <IconButton
        sx={{ bgcolor: 'primary.light', '&:hover': { bgcolor: 'white' } }}
        onClick={onClick}
      >
        {icon}
      </IconButton>
    );
  }

  return (
    <Grow
      in={open}
      style={{ transformOrigin: '0 0 0' }}
      {...(open ? { timeout: 200 * order } : {})}
    >
      <Box pl={order == 0 ? 3 : 1} {...boxProps}>
        <Tooltip title={title} arrow>
          <Paper
            elevation={2}
            sx={{ borderRadius: '50%', bgcolor: '#ffffff00' }}
          >
            {href != undefined ? (
              <Link
                href={href}
                rel={'noopener noreferrer'}
                target={newTab ? '_blank' : undefined}
              >
                {button}
              </Link>
            ) : (
              button
            )}
          </Paper>
        </Tooltip>
      </Box>
    </Grow>
  );
};

export type SpeedButtonControlledProps = Omit<
  SpeedButtonProps,
  'open' | 'order'
>;

interface SpeedDialProps {
  actions: SpeedButtonControlledProps[];
}

const SpeedDial = ({ actions }: SpeedDialProps) => {
  const [open, setOpen] = useState(false);

  return (
    <ClickAwayListener onClickAway={() => setOpen(false)}>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'row',
        }}
        onMouseLeave={() => setOpen(false)}
      >
        <Paper
          elevation={open ? 2 : 0}
          sx={{ borderRadius: '50%', bgcolor: '#ffffff00' }}
        >
          <IconButton
            onClick={() => setOpen(!open)}
            onMouseEnter={() => setOpen(true)}
          >
            <Add />
          </IconButton>
        </Paper>
        <Box position={'relative'}>
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              display: 'flex',
              flexDirection: 'row',
            }}
          >
            {actions.map((action, index) => (
              <SpeedDialButton
                key={action.title}
                open={open}
                order={index}
                onClick={() => setOpen(false)}
                {...action}
              />
            ))}
          </Box>
        </Box>
      </Box>
    </ClickAwayListener>
  );
};

export default SpeedDial;
