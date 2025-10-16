import React, { FC, useState } from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';

import MemberCard from '../MemberCard';
import { GroupMember, User } from '@/types';
import { CardList } from '@/components';
import useApiSWR from '@/hooks/useApiSWR';
import AddMemberAutocomplete from '../AddMemberAutocomplete';
import useFuse from '@/helpers/useFuse';

interface MemberListProps {
  groupId: string;
}

const MemberList = ({ groupId }: MemberListProps) => {
  const { data: members, error } = useApiSWR<GroupMember[]>(
    'Could not fetch group members',
    `/api/v1.0/groups/${groupId}/members`,
    () => getMembers(groupId)
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<GroupMember>(members || [], search);

  const orderedMembers = (searchedData || []).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );

  return (
    <>
      <Box gap={1} mb={1} display={'flex'} justifyContent={'space-between'}>
        <TextField
          size={'small'}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          label='Search'
        />
        <AddMemberAutocomplete groupId={groupId} />
      </Box>
      <CardList<{ member: GroupMember }>
        data={(orderedMembers || []).map((m) => {
          return { member: m };
        })}
        Card={MemberCard}
        keyGetter={(m) => m.member.user.id}
      />
    </>
  );
};

const getMembers = async (groupId: string) => {
  return await fetch(`/api/v1.0/groups/${groupId}/members`, { method: 'GET' });
};

export default MemberList;
