'use client';

import useApiSWR from '@/hooks/useApiSWR';
import { Skeleton, Typography } from '@mui/material';
import { ServerLocalMetadata } from '@/types';

const ServerName = () => {
  const {
    data: serverName,
    error,
    isLoading,
  } = useApiSWR<ServerLocalMetadata[]>(
    'Failed to fetch server name',
    '/api/server-name',
    async () => await fetch('/api/v1.0/server/localMetadata/history')
  );

  const mostRecentlyUpdatedMetadata = serverName?.sort(
    (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
  )?.[0];

  return (
    <Typography variant='h6' component='div' sx={{ flexGrow: 1 }} gutterBottom>
      {isLoading ? <Skeleton /> : mostRecentlyUpdatedMetadata?.name || 'Origin'}
    </Typography>
  );
};

export default ServerName;
