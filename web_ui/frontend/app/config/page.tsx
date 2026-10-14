'use client';

// The configuration editor used to live at /config; it's been moved under
// /settings/config (it is an administration page, and the Settings shell is
// where the administration menu lives). This page exists only to redirect
// anyone with a stale bookmark.

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Box, CircularProgress, Stack, Typography } from '@mui/material';

const Page = () => {
  const router = useRouter();
  useEffect(() => {
    router.replace('/settings/config/');
  }, [router]);
  return (
    <Box display='flex' justifyContent='center' p={6}>
      <Stack spacing={2} alignItems='center'>
        <CircularProgress size={24} />
        <Typography variant='body2' color='text.secondary'>
          Configuration has moved. Redirecting to /settings/config/…
        </Typography>
      </Stack>
    </Box>
  );
};

export default Page;
