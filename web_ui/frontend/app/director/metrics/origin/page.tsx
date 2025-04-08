'use client';

import OriginMetricPage from '@/components/graphs/OriginMetricPage';
import { Suspense, useState, useEffect } from 'react';
import { Skeleton } from '@mui/material';
import { useSearchParams } from 'next/navigation';

const RemoteOriginPage = () => {
  const params = useSearchParams();
  const serverName = params.get('server_name') || undefined;

  return <OriginMetricPage server_name={serverName} />;
};

const Page = () => {
  return (
    <Suspense fallback={<Skeleton />}>
      <RemoteOriginPage />
    </Suspense>
  );
};

export default Page;
