'use client';

import React, { useState } from 'react';

import { CardList } from '@/components';
import GroupCard from './components/GroupCard';
import useApiSWR from '@/hooks/useApiSWR';
import { Group, User } from '@/types';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Box, Button, TextField } from '@mui/material';
import Link from 'next/link';
import useFuse from '@/helpers/useFuse';

const Page = () => {
  const { data } = useApiSWR<Group[]>(
    'Could not fetch groups',
    '/api/v1.0/groups',
    async () => {
      return await fetch('/api/v1.0/groups', { method: 'GET' });
    }
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<Group>(data || [], search);

  return (
    <>
      <SettingHeader
        title={'Groups'}
        description={'Used for access control.'}
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
            Add Group
          </Button>
        </Link>
      </Box>
      <CardList<{ group: Group }>
        data={(searchedData || []).map((g) => {
          return { group: g };
        })}
        Card={GroupCard}
        keyGetter={(g) => g.group.id}
      />
    </>
  );
};

export default Page;
