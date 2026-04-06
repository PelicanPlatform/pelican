'use client';

import React, { useState } from 'react';

import useServiceSWR from '@/hooks/useServiceSWR';
import { UserService, User } from '@/helpers/api';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Box, Button, TextField } from '@mui/material';
import Link from 'next/link';
import useFuse from '@/helpers/useFuse';
import { DateTime } from 'luxon';
import UserTable from './components/UserTable';

const View = () => {
  const { data, mutate } = useServiceSWR(
    'Could not fetch users.',
    UserService,
    'getAll',
    []
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<User>(data || [], search);

  const sortedData = (searchedData || []).sort(
    (a, b) =>
      DateTime.fromISO(b.createdAt).toMillis() -
      DateTime.fromISO(a.createdAt).toMillis()
  );

  return (
    <>
      <Box mb={1} display={'flex'} justifyContent={'space-between'}>
        <TextField
          size={'small'}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          label='Search'
        />
        <Link href='./add/'>
          <Button variant='contained' color='primary'>
            Add User
          </Button>
        </Link>
      </Box>
      <UserTable data={sortedData} mutate={mutate} />
    </>
  );
};

export default View;
