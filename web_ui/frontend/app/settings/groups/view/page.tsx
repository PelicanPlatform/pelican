import React, { Suspense } from 'react';
import { Breadcrumbs, Skeleton, Typography } from '@mui/material';

import View from './view';
import Link from 'next/link';
import SettingHeader from '@/app/settings/components/SettingHeader';

export const metadata = {
  title: 'View Group',
};

const Page = () => (
  <>
    <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
      <Link href={'../'}>Groups</Link>
      <Typography sx={{ color: 'text.primary' }}>View</Typography>
    </Breadcrumbs>
    <Suspense
      fallback={
        <Skeleton variant='rectangular' width={'100%'} height={'600px'} />
      }
    >
      <View />
    </Suspense>
  </>
);

export default Page;
