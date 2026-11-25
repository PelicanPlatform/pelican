import { Skeleton } from '@mui/material';
import React, { Suspense } from 'react';

import View from './view';

export const metadata = {
  title: 'Edit User',
};

const Page = () => {
  return (
    <Suspense
      fallback={
        <Skeleton variant='rectangular' width={'100%'} height={'600px'} />
      }
    >
      <View />
    </Suspense>
  );
};

export default Page;
