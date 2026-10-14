'use client';

// User administration used to live under /settings/users; it's moved out to
// the top-level /users (it is a primary destination now, not an entry in the
// administration menu). This page exists only to redirect anyone with a stale
// bookmark.

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Box, CircularProgress, Stack, Typography } from '@mui/material';

const Page = () => {
  const router = useRouter();
  useEffect(() => {
    router.replace('/users/');
  }, [router]);
  return (
    <Box display='flex' justifyContent='center' p={6}>
      <Stack spacing={2} alignItems='center'>
        <CircularProgress size={24} />
        <Typography variant='body2' color='text.secondary'>
          User administration has moved. Redirecting to /users/…
        </Typography>
      </Stack>
    </Box>
  );
};

export default Page;
