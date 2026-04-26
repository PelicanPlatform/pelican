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

import React, { useContext } from 'react';
import { Box, Breadcrumbs, Skeleton, Stack, Typography } from '@mui/material';
import Link from 'next/link';
import useSWR from 'swr';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { Group } from '@/types';
import GroupDetail from '../components/GroupDetail';

interface GroupPageClientProps {
  id: string;
}

const fetchJson = async <T,>(path: string): Promise<T> => {
  const r = await fetch(path);
  if (!r.ok) {
    throw new Error(`${r.status} ${r.statusText}`);
  }
  return r.json();
};

const GroupPageClient: React.FC<GroupPageClientProps> = ({ id }) => {
  return (
    <AuthenticatedContent redirect>
      <FullPageContent id={id} />
    </AuthenticatedContent>
  );
};

const FullPageContent: React.FC<{ id: string }> = ({ id }) => {
  const dispatch = useContext(AlertDispatchContext);

  const {
    data: group,
    isLoading,
    error,
    mutate: mutateGroup,
  } = useSWR<Group | undefined>(id ? `group:${id}` : null, () =>
    alertOnError(
      () => fetchJson<Group>(`/api/v1.0/groups/${id}`),
      'Failed to load group',
      dispatch
    )
  );

  // The InlineAdminEdit candidate set for "admin = group" comes from the
  // caller's visible-groups list. Fetch it alongside the group itself.
  const { data: visibleGroups } = useSWR<Group[] | undefined>(
    'groups:visible',
    () =>
      alertOnError(
        () => fetchJson<Group[]>('/api/v1.0/groups'),
        'Failed to load groups list',
        dispatch
      )
  );

  return (
    <Box width='100%' maxWidth={960}>
      <Breadcrumbs aria-label='breadcrumb' sx={{ mb: 2 }}>
        <Link href='/groups/'>Groups</Link>
        <Typography color='text.primary'>{group?.name ?? id}</Typography>
      </Breadcrumbs>

      {error && !group && (
        <Typography color='error' role='alert'>
          {error.message ?? 'Failed to load group'}
        </Typography>
      )}

      {isLoading || !group ? (
        <Stack spacing={2}>
          <Skeleton variant='text' width={300} height={48} />
          <Skeleton variant='rounded' height={320} />
        </Stack>
      ) : (
        <Stack spacing={2}>
          <Typography variant='h4' sx={{ wordBreak: 'break-word' }}>
            {group.name}
          </Typography>
          <GroupDetail
            group={group}
            visibleGroups={visibleGroups ?? []}
            onChanged={() => {
              mutateGroup();
            }}
          />
        </Stack>
      )}
    </Box>
  );
};

export default GroupPageClient;
