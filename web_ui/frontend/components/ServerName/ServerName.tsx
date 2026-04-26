'use client';

import useApiSWR from '@/hooks/useApiSWR';
import { Skeleton, Typography } from '@mui/material';
import { ServerLocalMetadata } from '@/types';

interface ServerNameProps {
  defaultName: string;
}

const ServerName = ({ defaultName }: ServerNameProps) => {
  const { data: metadata, isLoading } = useApiSWR<ServerLocalMetadata>(
    'Failed to fetch server name',
    '/api/v1.0/server/localMetadata',
    async () => await fetch('/api/v1.0/server/localMetadata'),
    { fallbackData: { name: defaultName } as ServerLocalMetadata }
  );

  return (
    <Typography variant='h6' component='div' sx={{ flexGrow: 1 }} gutterBottom>
      {isLoading ? <Skeleton /> : metadata?.name ?? defaultName}
    </Typography>
  );
};

export default ServerName;
