'use client';

import React, { useState } from 'react';

import { CardList } from '@/components';
import UserCard from './components/UserCard';
import useApiSWR from '@/hooks/useApiSWR';
import { Group, User } from '@/types';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Box, Button, TextField } from '@mui/material';
import Link from 'next/link';
import useFuse from '@/helpers/useFuse';
import { DateTime } from 'luxon';

const Page = () => {
  const { data } = useApiSWR<User[]>(
    'Could no fetch users',
    '/api/v1.0/users',
    async () => {
      return await fetch('/api/v1.0/users', { method: 'GET' });
    }
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
      <SettingHeader
        title={'Users'}
        description={'Users of this Pelican service.'}
      />
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
      <CardList<{ user: User }>
        data={(sortedData || []).map((u) => {
          return { user: u };
        })}
        Card={UserCard}
        keyGetter={(u) => u.user.id}
      />
    </>
  );
};

export default Page;
