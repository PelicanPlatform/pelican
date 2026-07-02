/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

// Group management used to live under /settings/groups; it's been
// consolidated under /groups (top-level — groups are server-wide, not
// origin-specific). This page exists only to redirect anyone with a
// stale bookmark.

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Box, CircularProgress, Stack, Typography } from '@mui/material';

const Page = () => {
  const router = useRouter();
  useEffect(() => {
    router.replace('/groups/');
  }, [router]);
  return (
    <Box display='flex' justifyContent='center' p={6}>
      <Stack spacing={2} alignItems='center'>
        <CircularProgress size={24} />
        <Typography variant='body2' color='text.secondary'>
          Group management has moved. Redirecting to /groups/…
        </Typography>
      </Stack>
    </Box>
  );
};

export default Page;
