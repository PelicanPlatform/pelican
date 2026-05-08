'use client';

import { useSearchParams } from 'next/navigation';
import GroupPage from '@/app/settings/groups/components/GroupPage/GroupPage';
import { Box, Link, Typography } from '@mui/material';

const View = () => {
  const searchParams = useSearchParams();
  const groupId = searchParams.get('id');

  if (!groupId) {
    return (
      <Box>
        <Typography variant={'h6'} color={'error'}>
          No group ID provided. Return to <Link href={'../'}>Groups</Link>.
        </Typography>
      </Box>
    );
  }

  return <GroupPage groupId={groupId} />;
};

export default View;
