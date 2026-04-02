/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import React, { useState } from 'react';

import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  IconButton,
  TextField,
  Typography,
} from '@mui/material';
import { Delete, Refresh } from '@mui/icons-material';
import Link from 'next/link';
import useApiSWR from '@/hooks/useApiSWR';
import useFuse from '@/helpers/useFuse';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

interface CollectionSummary {
  id: string;
  name: string;
  description: string;
  namespace: string;
  visibility: string;
  owner: string;
  createdAt: string;
  updatedAt: string;
}

const Page = () => {
  const {
    data: collections,
    error,
    mutate,
  } = useApiSWR<CollectionSummary[]>(
    'Could not fetch collections',
    '/api/v1.0/origin_ui/collections',
    async () => {
      return await fetch('/api/v1.0/origin_ui/collections', { method: 'GET' });
    }
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<CollectionSummary>(collections || [], search);

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this collection?')) return;
    const resp = await fetch(`/api/v1.0/origin_ui/collections/${id}`, {
      method: 'DELETE',
    });
    if (resp.ok) {
      mutate();
    }
  };

  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin', 'user']}>
      <Box width={'100%'}>
        <Box
          mb={2}
          display={'flex'}
          justifyContent={'space-between'}
          alignItems={'center'}
        >
          <Typography variant='h4'>Collections</Typography>
          <Box display='flex' gap={1}>
            <IconButton onClick={() => mutate()}>
              <Refresh />
            </IconButton>
            <Link href='./collections/create'>
              <Button variant='contained' color='primary'>
                Create Collection
              </Button>
            </Link>
          </Box>
        </Box>
        <Box mb={2}>
          <TextField
            size={'small'}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            label='Search'
            fullWidth
          />
        </Box>
        {error && (
          <Typography color='error'>
            Failed to load collections: {error.message}
          </Typography>
        )}
        {searchedData && searchedData.length === 0 && (
          <Typography color='text.secondary'>
            No collections found. Create one to get started.
          </Typography>
        )}
        {(searchedData || []).map((c) => (
          <Card key={c.id} sx={{ mb: 1 }}>
            <CardContent
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <Box>
                <Typography variant='h6'>{c.name}</Typography>
                {c.description && (
                  <Typography variant='body2' color='text.secondary'>
                    {c.description}
                  </Typography>
                )}
                <Box mt={0.5} display='flex' gap={1} alignItems='center'>
                  <Chip
                    label={c.visibility}
                    size='small'
                    color={c.visibility === 'public' ? 'success' : 'default'}
                  />
                  <Typography variant='caption' color='text.secondary'>
                    Namespace: {c.namespace}
                  </Typography>
                </Box>
              </Box>
              <IconButton
                color='error'
                onClick={() => handleDelete(c.id)}
                title='Delete collection'
              >
                <Delete />
              </IconButton>
            </CardContent>
          </Card>
        ))}
      </Box>
    </AuthenticatedContent>
  );
};

export default Page;
