import { Box, Tooltip } from '@mui/material';
import Link from 'next/link';
import IconButton from '@mui/material/IconButton';
import { Dashboard } from '@mui/icons-material';
import { ReactNode } from 'react';

interface ButtonLinkProps {
  title: string;
  href: string;
  children: ReactNode;
}

export const ButtonLink = ({ title, href, children }: ButtonLinkProps) => {
  return (
    <Box pt={1}>
      <Tooltip title={title} placement={'right'}>
        <Link href={href}>
          <IconButton>{children}</IconButton>
        </Link>
      </Tooltip>
    </Box>
  );
};
