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

import React, { useContext, useState } from 'react';

import {
  Autocomplete,
  Box,
  Breadcrumbs,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
} from '@mui/material';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { AlertDispatchContext } from '@/components/AlertProvider';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { alertOnError } from '@/helpers/util';
import { fetchApi } from '@/helpers/api';
import useApiSWR from '@/hooks/useApiSWR';
import { Group } from '@/types';

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [namespace, setNamespace] = useState('');
  const [visibility, setVisibility] = useState<'private' | 'public'>(
    'private'
  );

  // Group autocomplete for ACLs
  const [readGroupId, setReadGroupId] = useState('');
  const [writeGroupId, setWriteGroupId] = useState('');
  const [ownerGroupId, setOwnerGroupId] = useState('');

  const { data: groups } = useApiSWR<Group[]>(
    'Could not fetch groups',
    '/api/v1.0/groups',
    async () => {
      return await fetch('/api/v1.0/groups', { method: 'GET' });
    }
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      // 1. Create collection
      const response = await alertOnError(
        async () =>
          fetchApi(async () =>
            fetch('/api/v1.0/origin_ui/collections', {
              method: 'POST',
              body: JSON.stringify({
                name,
                description,
                namespace,
                visibility,
              }),
            })
          ),
        'Error Creating Collection',
        dispatch
      );

      if (!response?.ok) {
        setIsSubmitting(false);
        return;
      }

      const collection = await response.json();
      const collectionId = collection.id;

      // 2. Grant ACLs if groups were selected
      const aclPromises = [];
      if (readGroupId) {
        aclPromises.push(
          grantAcl(collectionId, readGroupId, 'read', dispatch)
        );
      }
      if (writeGroupId) {
        aclPromises.push(
          grantAcl(collectionId, writeGroupId, 'write', dispatch)
        );
      }
      if (ownerGroupId) {
        aclPromises.push(
          grantAcl(collectionId, ownerGroupId, 'owner', dispatch)
        );
      }
      await Promise.all(aclPromises);

      router.push('/origin/collections');
    } catch {
      // Error already dispatched
    } finally {
      setIsSubmitting(false);
    }
  };

  const groupOptions = (groups || []).map((g) => ({
    label: `${g.name} (${g.id})`,
    id: g.id,
  }));

  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin']}>
      <Box width={'100%'} maxWidth={600}>
        <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
          <Link href='/origin/collections'>Collections</Link>
          <Typography sx={{ color: 'text.primary' }}>Create</Typography>
        </Breadcrumbs>
        <Typography variant='h4' mb={2}>
          Create Collection
        </Typography>
        <form onSubmit={handleSubmit}>
          <TextField
            label='Name'
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            fullWidth
            sx={{ mb: 2 }}
            helperText='A short, human-readable name for this collection.'
          />
          <TextField
            label='Namespace'
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
            required
            fullWidth
            sx={{ mb: 2 }}
            helperText='The path prefix for this collection (e.g. /my-project/data).'
            placeholder='/my-project/data'
          />
          <TextField
            label='Description'
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            fullWidth
            multiline
            rows={3}
            sx={{ mb: 2 }}
          />
          <FormControl fullWidth sx={{ mb: 3 }}>
            <InputLabel>Visibility</InputLabel>
            <Select
              value={visibility}
              label='Visibility'
              onChange={(e) =>
                setVisibility(e.target.value as 'private' | 'public')
              }
            >
              <MenuItem value='private'>Private</MenuItem>
              <MenuItem value='public'>Public</MenuItem>
            </Select>
          </FormControl>

          <Typography variant='h6' mb={1}>
            Group ACLs (Optional)
          </Typography>
          <Typography variant='body2' color='text.secondary' mb={2}>
            Assign existing groups as readers, writers, or owners. You can also
            set these later.
          </Typography>

          <Autocomplete
            options={groupOptions}
            renderInput={(params) => (
              <TextField {...params} label='Reader Group' />
            )}
            onChange={(_e, val) => setReadGroupId(val?.id || '')}
            sx={{ mb: 2 }}
            isOptionEqualToValue={(option, value) => option.id === value.id}
          />
          <Autocomplete
            options={groupOptions}
            renderInput={(params) => (
              <TextField {...params} label='Writer Group' />
            )}
            onChange={(_e, val) => setWriteGroupId(val?.id || '')}
            sx={{ mb: 2 }}
            isOptionEqualToValue={(option, value) => option.id === value.id}
          />
          <Autocomplete
            options={groupOptions}
            renderInput={(params) => (
              <TextField {...params} label='Owner Group' />
            )}
            onChange={(_e, val) => setOwnerGroupId(val?.id || '')}
            sx={{ mb: 3 }}
            isOptionEqualToValue={(option, value) => option.id === value.id}
          />

          <Box display='flex' gap={2}>
            <Button
              type='submit'
              variant='contained'
              color='primary'
              disabled={isSubmitting || !name || !namespace}
            >
              {isSubmitting ? 'Creating...' : 'Create Collection'}
            </Button>
            <Link href='/origin/collections'>
              <Button variant='outlined'>Cancel</Button>
            </Link>
          </Box>
        </form>
      </Box>
    </AuthenticatedContent>
  );
};

const grantAcl = async (
  collectionId: string,
  groupId: string,
  role: string,
  dispatch: React.Dispatch<any>
) => {
  await alertOnError(
    async () =>
      fetchApi(async () =>
        fetch(`/api/v1.0/origin_ui/collections/${collectionId}/acl`, {
          method: 'POST',
          body: JSON.stringify({ groupId, role }),
        })
      ),
    `Error granting ${role} ACL`,
    dispatch
  );
};

export default Page;
