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

// Per-group detail page. We use a query-string id (`/groups/view/?id=…`)
// rather than a dynamic-segment route (`/groups/[id]/`) because the
// project ships a static export (next.config.js: `output: 'export'`); Next 15
// requires every dynamic segment to enumerate its params at build time, and
// group IDs are user data that doesn't exist at build time. The rest of the
// admin pages in this project (e.g. /settings/users/edit/) use the same
// query-string pattern for the same reason.

import React, { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { Skeleton, Typography } from '@mui/material';

import GroupPageClient from './GroupPageClient';

// Inner component reads the search params; wrapped in Suspense by Page below
// because Next 15 + `output: 'export'` refuses to prerender any component
// that calls useSearchParams() outside a Suspense boundary.
const ViewBody: React.FC = () => {
  const searchParams = useSearchParams();
  const id = searchParams.get('id');
  if (!id) {
    return (
      <Typography>
        This page must be opened with a `?id=…` query parameter.
      </Typography>
    );
  }
  return <GroupPageClient id={id} />;
};

const Page = () => (
  <Suspense
    fallback={
      <Skeleton variant='rectangular' width={'100%'} height={'600px'} />
    }
  >
    <ViewBody />
  </Suspense>
);

export default Page;
