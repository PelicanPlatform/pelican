'use client';

import React, { useState } from 'react';
import { Box, Button, TextField } from '@mui/material';
import Link from 'next/link';
import useFuse from '@/helpers/useFuse';
import useServiceSWR from '@/hooks/useServiceSWR';
import { GroupService, Group } from '@/helpers/api';
import GroupTable from './components/GroupTable';

const View = () => {
  const { data } = useServiceSWR(
    'Could not fetch groups.',
    GroupService,
    'getAll',
    []
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<Group>(data || [], search);

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
            Add Group
          </Button>
        </Link>
      </Box>
      <GroupTable data={searchedData} />
    </>
  );
};

export default View;
