'use client';

import React, { useState } from 'react';

import useServiceSWR from '@/hooks/useServiceSWR';
import { UserService, User } from '@/helpers/api';
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
      <UserTable data={searchedData} mutate={mutate} />
    </>
  );
};

export default View;
