'use client';

import useApiSWR from '@/hooks/useApiSWR';
import { Skeleton, Typography } from '@mui/material';
import { ServerLocalMetadata } from '@/types';

interface ServerNameProps {
  defaultName: string;
}

const ServerName = ({ defaultName }: ServerNameProps) => {
  const {
    data: metadataHistory,
    error,
    isLoading,
  } = useApiSWR<ServerLocalMetadata[]>(
    'Failed to fetch server name',
    '/api/server-name',
    async () => await fetch('/api/v1.0/server/localMetadata/history'),
    { fallbackData: defaultName }
  );

  return (
    <Typography variant='h6' component='div' sx={{ flexGrow: 1 }} gutterBottom>
      {isLoading ? <Skeleton /> : metadataHistory?.[0]?.name || defaultName}
    </Typography>
  );
};

export default ServerName;
