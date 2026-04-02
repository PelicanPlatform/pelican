/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItem,
  ListItemText,
  TextField,
  Typography,
} from '@mui/material';
import { ContentCopy, Delete, PersonAdd, Refresh } from '@mui/icons-material';
import { AlertDispatchContext } from '@/components/AlertProvider';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { alertOnError } from '@/helpers/util';
import { fetchApi } from '@/helpers/api';
import useApiSWR from '@/hooks/useApiSWR';
import { Group, GroupInviteLink } from '@/types';

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);

  const {
    data: groups,
    error,
    mutate,
  } = useApiSWR<Group[]>('Could not fetch groups', '/api/v1.0/groups', async () => {
    return await fetch('/api/v1.0/groups', { method: 'GET' });
  });

  // Create group dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupDescription, setNewGroupDescription] = useState('');
  const [creating, setCreating] = useState(false);

  // Invite link dialog
  const [inviteDialogGroupId, setInviteDialogGroupId] = useState('');
  const [inviteLinks, setInviteLinks] = useState<GroupInviteLink[]>([]);
  const [generatedToken, setGeneratedToken] = useState('');
  const [loadingInvites, setLoadingInvites] = useState(false);

  const handleCreateGroup = async () => {
    if (!newGroupName) return;
    setCreating(true);
    try {
      const response = await alertOnError(
        async () =>
          fetchApi(async () =>
            fetch('/api/v1.0/groups', {
              method: 'POST',
              body: JSON.stringify({
                id: '',
                name: newGroupName,
                description: newGroupDescription,
              }),
            })
          ),
        'Error Creating Group',
        dispatch
      );
      if (response?.ok) {
        await mutate();
        setNewGroupName('');
        setNewGroupDescription('');
        setCreateOpen(false);
      }
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteGroup = async (id: string) => {
    if (!confirm('Are you sure you want to delete this group?')) return;
    await alertOnError(
      async () =>
        fetchApi(async () =>
          fetch(`/api/v1.0/groups/${id}`, { method: 'DELETE' })
        ),
      'Error Deleting Group',
      dispatch
    );
    mutate();
  };

  const handleOpenInvites = async (groupId: string) => {
    setInviteDialogGroupId(groupId);
    setGeneratedToken('');
    setLoadingInvites(true);
    try {
      const resp = await fetch(`/api/v1.0/groups/${groupId}/invite-links`, {
        method: 'GET',
      });
      if (resp.ok) {
        setInviteLinks(await resp.json());
      } else {
        setInviteLinks([]);
      }
    } catch {
      setInviteLinks([]);
    } finally {
      setLoadingInvites(false);
    }
  };

  const handleGenerateInvite = async () => {
    if (!inviteDialogGroupId) return;
    try {
      const response = await alertOnError(
        async () =>
          fetchApi(async () =>
            fetch(
              `/api/v1.0/groups/${inviteDialogGroupId}/invite-links`,
              {
                method: 'POST',
                body: JSON.stringify({
                  isSingleUse: false,
                  expiresInHours: 168,
                }),
              }
            )
          ),
        'Error Generating Invite Link',
        dispatch
      );
      if (response?.ok) {
        const data = await response.json();
        setGeneratedToken(data.inviteToken || '');
        // Refresh links list
        handleOpenInvites(inviteDialogGroupId);
      }
    } catch {
      // Error already dispatched
    }
  };

  const handleRevokeInvite = async (linkId: string) => {
    await alertOnError(
      async () =>
        fetchApi(async () =>
          fetch(
            `/api/v1.0/groups/${inviteDialogGroupId}/invite-links/${linkId}`,
            { method: 'DELETE' }
          )
        ),
      'Error Revoking Invite Link',
      dispatch
    );
    handleOpenInvites(inviteDialogGroupId);
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
          <Typography variant='h4'>Groups</Typography>
          <Box display='flex' gap={1}>
            <IconButton onClick={() => mutate()}>
              <Refresh />
            </IconButton>
            <Button
              variant='contained'
              color='primary'
              onClick={() => setCreateOpen(true)}
            >
              Create Group
            </Button>
          </Box>
        </Box>

        {error && (
          <Typography color='error'>
            Failed to load groups: {error.message}
          </Typography>
        )}
        {groups && groups.length === 0 && (
          <Typography color='text.secondary'>
            No groups found. Create one to get started.
          </Typography>
        )}
        {(groups || []).map((g) => (
          <Card key={g.id} sx={{ mb: 1 }}>
            <CardContent
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <Box>
                <Typography variant='h6'>{g.name}</Typography>
                {g.description && (
                  <Typography variant='body2' color='text.secondary'>
                    {g.description}
                  </Typography>
                )}
                <Chip
                  label={`ID: ${g.id}`}
                  size='small'
                  sx={{ mt: 0.5 }}
                />
              </Box>
              <Box display='flex' gap={1}>
                <IconButton
                  title='Manage invite links'
                  onClick={() => handleOpenInvites(g.id)}
                >
                  <PersonAdd />
                </IconButton>
                <IconButton
                  title='Delete group'
                  onClick={() => handleDeleteGroup(g.id)}
                  color='error'
                >
                  <Delete />
                </IconButton>
              </Box>
            </CardContent>
          </Card>
        ))}
      </Box>

      {/* Create Group Dialog */}
      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        maxWidth='sm'
        fullWidth
      >
        <DialogTitle>Create New Group</DialogTitle>
        <DialogContent>
          <TextField
            label='Group Name'
            value={newGroupName}
            onChange={(e) => setNewGroupName(e.target.value)}
            required
            fullWidth
            sx={{ mt: 1, mb: 2 }}
          />
          <TextField
            label='Description'
            value={newGroupDescription}
            onChange={(e) => setNewGroupDescription(e.target.value)}
            fullWidth
            multiline
            rows={2}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button
            variant='contained'
            onClick={handleCreateGroup}
            disabled={creating || !newGroupName}
          >
            {creating ? 'Creating...' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Invite Links Dialog */}
      <Dialog
        open={!!inviteDialogGroupId}
        onClose={() => setInviteDialogGroupId('')}
        maxWidth='sm'
        fullWidth
      >
        <DialogTitle>Invite Links</DialogTitle>
        <DialogContent>
          {generatedToken && (
            <Box mb={2} p={2} sx={{ bgcolor: 'success.light', borderRadius: 1 }}>
              <Typography variant='body2' fontWeight='bold' mb={1}>
                New invite token (copy now, it won&apos;t be shown again):
              </Typography>
              <Box display='flex' alignItems='center' gap={1}>
                <TextField
                  value={generatedToken}
                  fullWidth
                  size='small'
                  slotProps={{
                    input: {
                      readOnly: true,
                    },
                  }}
                />
                <IconButton
                  onClick={() =>
                    navigator.clipboard.writeText(generatedToken)
                  }
                >
                  <ContentCopy />
                </IconButton>
              </Box>
            </Box>
          )}

          <Button
            variant='outlined'
            onClick={handleGenerateInvite}
            sx={{ mb: 2 }}
          >
            Generate New Invite Link
          </Button>

          {loadingInvites ? (
            <Typography>Loading...</Typography>
          ) : inviteLinks.length === 0 ? (
            <Typography color='text.secondary'>
              No invite links yet.
            </Typography>
          ) : (
            <List dense>
              {inviteLinks.map((link) => (
                <ListItem
                  key={link.id}
                  secondaryAction={
                    !link.revoked && (
                      <IconButton
                        edge='end'
                        title='Revoke'
                        onClick={() => handleRevokeInvite(link.id)}
                        color='error'
                      >
                        <Delete />
                      </IconButton>
                    )
                  }
                >
                  <ListItemText
                    primary={`${link.isSingleUse ? 'Single-use' : 'Multi-use'} — Expires: ${new Date(link.expiresAt).toLocaleDateString()}`}
                    secondary={
                      link.revoked
                        ? 'Revoked'
                        : link.redeemedBy
                          ? `Redeemed by ${link.redeemedBy}`
                          : 'Active'
                    }
                  />
                </ListItem>
              ))}
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInviteDialogGroupId('')}>Close</Button>
        </DialogActions>
      </Dialog>
    </AuthenticatedContent>
  );
};

export default Page;
