'use client';

import React, { ReactNode, useMemo, useRef, useState } from 'react';
import {
  Link,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
} from '@mui/material';
import RailItemButton from '@/components/layout/Navigation/Sidebar/RailItemButton';
import {
  Api,
  BugReport,
  Description,
  Email,
  GitHub,
  Help,
  Link as LinkIcon,
} from '@mui/icons-material';
import useSWR from 'swr';

import { evaluateOrReturn } from '@/helpers/util';

const AboutMenu = () => {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  const { data: supportContacts } = useSWR<DirectorSupportContacts>(
    'directorSupportContacts',
    getDirectorSupportContacts,
    { fallbackData: {} }
  );

  const supportMenuExtension = useMemo<MenuItemProps[]>(() => {
    return getDirectorMenuItemProps(supportContacts || {});
  }, [supportContacts]);

  return (
    <>
      <RailItemButton
        id={'about-menu-button'}
        ref={menuRef}
        label={'Help'}
        icon={<Help />}
        onClick={() => setOpen(!open)}
        aria-haspopup={'menu'}
        aria-expanded={open}
        aria-controls={open ? 'about-menu' : undefined}
      />
      <Menu
        id={'about-menu'}
        aria-labelledby={'about-menu-button'}
        sx={{ ml: 4 }}
        anchorEl={menuRef.current}
        open={open}
        onClose={() => setOpen(false)}
        anchorOrigin={{
          vertical: 'center',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'center',
          horizontal: 'left',
        }}
      >
        {[...actions, ...supportMenuExtension].map((action, index) => {
          return (
            <AboutMenuItem key={action.title + index.toString()} {...action} />
          );
        })}
      </Menu>
    </>
  );
};

type DirectorSupportContacts = {
  email?: string;
  url?: string;
};

const getDirectorSupportContacts =
  async (): Promise<DirectorSupportContacts> => {
    const response = await fetch('/api/v1.0/director_ui/contact');
    if (response.ok) {
      return await response.json();
    }
    return {};
  };

const getDirectorMenuItemProps = ({
  email,
  url,
}: DirectorSupportContacts): MenuItemProps[] => {
  if (email && !url) {
    return [
      {
        icon: <Email />,
        title: 'Contact Support',
        href: `mailto:${email}`,
      },
    ];
  }

  if (!email && url) {
    return [
      {
        icon: <LinkIcon />,
        title: 'Contact Support',
        href: url,
      },
    ];
  }

  if (email && url) {
    return [
      {
        icon: <Email />,
        title: 'Email Support',
        href: `mailto:${email}`,
      },
      {
        icon: <LinkIcon />,
        title: 'Support Portal',
        href: url,
      },
    ];
  }

  return [];
};

const AboutMenuItem = ({ icon, title, href }: MenuItemProps) => {
  return (
    <Link
      href={evaluateOrReturn(href)}
      target={'_blank'}
      underline={'none'}
      rel={'noreferrer'}
      color={'inherit'}
    >
      <MenuItem key={evaluateOrReturn(title)}>
        <ListItemIcon>{icon}</ListItemIcon>
        <ListItemText>{evaluateOrReturn(title)}</ListItemText>
      </MenuItem>
    </Link>
  );
};

interface MenuItemProps {
  icon: ReactNode;
  title: string | (() => string);
  href: string | (() => string);
}

const actions: MenuItemProps[] = [
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
];

export const getVersionNumber = () => {
  const { version } = require('../../../../package.json');
  return version;
};

export default AboutMenu;
