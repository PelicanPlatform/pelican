import React, { useState, useMemo } from 'react';
import TextField from '@mui/material/TextField';
import Autocomplete from '@mui/material/Autocomplete';
import CircularProgress from '@mui/material/CircularProgress';
import { fetchApi } from '@/helpers/api';
import { User, GroupMember } from '@/types';
import useApiSWR from '@/hooks/useApiSWR';
import { Box } from '@mui/material';
import { Add } from '@mui/icons-material';
import { secureFetch } from '@/helpers/login';

interface AddMemberAutocompleteProps {
  groupId: string;
}

const AddMemberAutocomplete = ({ groupId }: AddMemberAutocompleteProps) => {
  const [inputValue, setInputValue] = useState('');
  const [value, setValue] = useState<User | null>(null);
  const [addingMember, setAddingMember] = useState(false);

  const {
    data: members,
    isLoading: membersIsLoading,
    mutate,
  } = useApiSWR<GroupMember[]>(
    'Could not fetch group members',
    `/api/v1.0/groups/${groupId}/members`,
    async () => fetch(`/api/v1.0/groups/${groupId}/members`, { method: 'GET' })
  );
  const { data: users, isLoading: usersIsLoading } = useApiSWR<User[]>(
    'Could not fetch group members',
    `/api/v1.0/users`,
    async () => fetch(`/api/v1.0/users`, { method: 'GET' })
  );

  const potentialMembers = useMemo(() => {
    if (members && users) {
      const memberIds = new Set(members.map((m) => m.user.id));
      return users.filter((u) => !memberIds.has(u.id));
    }
    return [];
  }, [members, users]);

  return (
    <Autocomplete
      sx={{ width: '100%' }}
      getOptionLabel={(option) => option?.username || ''}
      options={potentialMembers}
      value={value}
      loading={membersIsLoading || usersIsLoading || addingMember}
      onChange={async (_, value) => {
        _.stopPropagation();
        if (value) {
          setValue(value);
          setAddingMember(true);
          await addMemberToGroup(groupId, value.id);
          setAddingMember(false);
          mutate();
          setValue(null);
        }
      }}
      onInputChange={(_, value) => setInputValue(value)}
      renderInput={(params) => (
        <TextField
          {...params}
          size={'small'}
          label='Add member'
          InputProps={{
            ...params.InputProps,
            endAdornment: (
              <>
                {membersIsLoading || usersIsLoading ? (
                  <CircularProgress color='inherit' size={20} />
                ) : null}
                {params.InputProps.endAdornment}
              </>
            ),
          }}
        />
      )}
      renderOption={(props, option, state, ownerState) => {
        return (
          <li {...props} key={props.id}>
            <Box
              display={'flex'}
              justifyContent={'space-between'}
              width={'100%'}
            >
              <Box>{option.username}</Box>
              <Box>
                <Add />
              </Box>
            </Box>
          </li>
        );
      }}
    />
  );
};

const addMemberToGroup = async (groupId: string, userId: string) => {
  return await fetchApi(async () =>
    secureFetch(`/api/v1.0/groups/${groupId}/members`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ userId: userId }),
    })
  );
};

export default AddMemberAutocomplete;
