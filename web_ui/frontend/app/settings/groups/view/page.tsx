'use client';

import { useSearchParams } from 'next/navigation';
import React, { useState, useEffect, useContext, Suspense } from 'react';
import { Box, Breadcrumbs, Skeleton, Typography } from '@mui/material';
import Link from 'next/link';

import { Group } from '@/types';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { fetchApi } from '@/helpers/api';
import SettingHeader from '../../components/SettingHeader';
import MemberList from '../components/MemberList';
import { InformationSpan } from '@/components';

const PageContent = () => {
  const dispatch = useContext(AlertDispatchContext);
  const [group, setGroup] = useState<Group | undefined>(undefined);
  const searchParams = useSearchParams();
  const groupId = searchParams.get('id');

  useEffect(() => {
    (async () => {
      if (groupId) {
        const response = await alertOnError(
          async () => await fetchApi(() => getGroup(groupId)),
          'Failed to fetch group details',
          dispatch
        );
        if (response?.ok) {
          const groups = (await response.json()) as Group[];
          const group = groups.filter((x) => x.id == groupId)?.[0];
          setGroup(group);
        }
      }
    })();
  }, [dispatch, groupId]);

  return (
    <Box>
      <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
        <Link href={'../'}>Groups</Link>
        <Typography sx={{ color: 'text.primary' }}>View</Typography>
      </Breadcrumbs>
      <SettingHeader
        title={group?.name || 'Loading...'}
        description={group?.description}
      />
      {group ? (
        <MemberList groupId={group?.id} />
      ) : (
        <Skeleton variant='rectangular' width={'100%'} height={'500px'} />
      )}
      {group ? (
        <Box mt={2}>
          {information(group).map((info) => (
            <InformationSpan key={info.name} {...info} />
          ))}
        </Box>
      ) : (
        <Skeleton variant='rectangular' width={'100%'} height={'60px'} />
      )}
    </Box>
  );
};

const Page = () => (
  <Suspense
    fallback={
      <Skeleton variant='rectangular' width={'100%'} height={'600px'} />
    }
  >
    <PageContent />
  </Suspense>
);

// TODO: This should call a object endpoint, not a list endpoint
const getGroup = async (id: string): Promise<Response> => {
  return fetch(`/api/v1.0/groups`, { method: 'GET' });
};

const information = (g: Group) => [
  { name: 'Created By', value: g.createdBy },
  { name: 'Created At', value: new Date(g.createdAt).toLocaleString() },
];

export default Page;
