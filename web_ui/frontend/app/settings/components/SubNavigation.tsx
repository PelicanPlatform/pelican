'use client';

import { cloneElement, JSXElementConstructor, ReactElement } from 'react';
import NavigationConfiguration from '@/app/navigation';
import { StaticNavigationChildItemProps } from '@/components/layout/Navigation';
import Link from 'next/link';
import { Box, Typography } from '@mui/material';
import { evaluateOrReturn } from '@/helpers/util';
import { usePathname } from 'next/navigation';

const SubNavigation = () => {
  const pathname = usePathname();

  return (
    <Box>
      {NavigationConfiguration.settings.map((item) => {
        // Check in the pre render if we break the render rules
        if ('children' in item) {
          throw new Error('SubNavigation does not support children');
        }

        return (
          <NavigationItem navItem={item} key={evaluateOrReturn(item.title)} />
        );
      })}
    </Box>
  );
};

const NavigationItem = ({
  active,
  navItem,
}: {
  active?: boolean;
  navItem: StaticNavigationChildItemProps;
}) => {
  const { title, href, icon } = navItem;

  const iconWithProps = cloneElement(
    icon as ReactElement<any, string | JSXElementConstructor<any>>,
    { fontSize: 'small', color: active ? 'primary' : 'inherit' }
  );

  return (
    <Link href={evaluateOrReturn(href)}>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          px: 1,
          py: 0.5,
          backgroundColor: active ? '#f0f0f0' : 'transparent',
          borderRadius: '4px',
          '&:hover': {
            backgroundColor: '#f0f0f0',
          },
        }}
      >
        <Box display={'flex'} alignItems={'center'} justifyContent={'center'}>
          {iconWithProps}
          <Box>
            <span style={{ marginLeft: '8px' }}>{evaluateOrReturn(title)}</span>
          </Box>
        </Box>
      </Box>
    </Link>
  );
};

export default SubNavigation;
