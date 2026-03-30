

import { Skeleton } from '@mui/material';
import { Suspense } from 'react';

import

export const metadata = {
  title: 'Edit User'
};

const Page = () => {
  return (
    <Suspense fallback={<Skeleton />}>
      <
    </Suspense>
  )
}

export default Page;
