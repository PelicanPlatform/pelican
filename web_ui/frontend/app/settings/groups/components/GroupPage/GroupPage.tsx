'use client';

import React, { Suspense, useMemo, useContext } from 'react';
import { Skeleton, Box, Typography, IconButton, Link } from '@mui/material';
import { Group, GroupService, makeGroupMemberService } from '@/helpers/api';
import SettingHeader from '@/app/settings/components/SettingHeader';
import useServiceSWR from '@/hooks/useServiceSWR';
import GroupMemberTableWrapper from '@/app/settings/groups/components/GroupMemberTableWrapper';
import ConfirmButton from '@chtc/web-components/ConfirmButton';
import { Delete, Edit } from '@mui/icons-material';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { useRouter } from 'next/navigation';

interface GroupPageProps {
  groupId: string;
}

const GroupPage = ({ groupId }: GroupPageProps) => {
  const { data: group } = useServiceSWR(
    'Could not fetch group.',
    GroupService,
    'getOne',
    [groupId],
    { suspense: true }
  );

  return (
    <Box>
      <SettingHeader
        title={group?.name || 'Loading...'}
        action={<Actions group={group} />}
        description={group?.description}
      />
      {group ? (
        <Box>
          {information(group).map((info) => (
            <Box key={info.name} mb={1}>
              <Typography variant={'subtitle2'}>
                {info.name}: {info.value}
              </Typography>
            </Box>
          ))}
        </Box>
      ) : (
        <Skeleton variant='rectangular' width={'100%'} height={'60px'} />
      )}
      <Suspense
        fallback={
          <Skeleton variant='rectangular' width={'100%'} height={'400px'} />
        }
      >
        <GroupMemberTableWrapper groupId={groupId} />
      </Suspense>
    </Box>
  );
};

const information = (g: Group) => [
  { name: 'Created By', value: g.createdBy },
  { name: 'Created At', value: new Date(g.createdAt).toLocaleString() },
];

const Actions = ({ group }: { group?: Group }) => {
  const dispatch = useContext(AlertDispatchContext);
  const router = useRouter();

  const handleDelete = async () => {
    if (!group) return;

    try {
      await alertOnError(
        () => GroupService.delete(group.id),
        `Error Deleting Group`,
        dispatch,
        true
      );
    } catch (error) {
      return;
    }
    router.push(`../`);
  };

  return (
    <>
      <IconButton href={'../edit?id=' + group?.id}>
        <Edit />
      </IconButton>
      <ConfirmButton onConfirm={handleDelete} color={'error'}>
        <Delete />
      </ConfirmButton>
    </>
  );
};

export default GroupPage;
