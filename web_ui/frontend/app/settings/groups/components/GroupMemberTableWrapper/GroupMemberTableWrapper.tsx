import React, { useEffect, useMemo, useState } from 'react';
import { GroupMember, makeGroupMemberService } from '@/helpers/api';
import useServiceSWR from '@/hooks/useServiceSWR';
import GroupMemberTable from '@/app/settings/groups/components/GroupMemberTable';
import useFuse from '@/helpers/useFuse';
import { Box, TextField } from '@mui/material';
import AddMemberAutocomplete from '@/app/settings/groups/components/AddMemberAutocomplete';

interface GroupMemberTableWrapperProps {
  groupId: string;
}

const GroupMemberTableWrapper = ({ groupId }: GroupMemberTableWrapperProps) => {
  const groupMemberService = makeGroupMemberService(groupId);
  const { data: groupMembers, mutate } = useServiceSWR(
    'Could not fetch group members.',
    groupMemberService,
    'getAll',
    [],
    { suspense: true }
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<GroupMember>(groupMembers || [], search);

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
      <GroupMemberTable data={searchedData} mutate={mutate} groupId={groupId} />
    </>
  );
};

export default GroupMemberTableWrapper;
