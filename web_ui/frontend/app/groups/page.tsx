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
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import {
  Delete,
  ExpandMore,
  OpenInNew,
  Refresh,
  Search,
  Clear,
} from '@mui/icons-material';
import Link from 'next/link';
import useSWR from 'swr';
import ConfirmButton from '@chtc/web-components/ConfirmButton';
import { AlertDispatchContext } from '@/components/AlertProvider';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { alertOnError } from '@/helpers/util';
import { fetchApi } from '@/helpers/api';
import useApiSWR from '@/hooks/useApiSWR';
import { Group } from '@/types';
import { Me, MeService } from '@/helpers/api';
import { getUser } from '@/helpers/login';
import GroupDetail from './components/GroupDetail';
import UserPill from './components/UserPill';

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);

  const {
    data: groups,
    error,
    mutate,
  } = useApiSWR<Group[]>(
    'Could not fetch groups',
    '/api/v1.0/groups',
    async () => fetch('/api/v1.0/groups', { method: 'GET' })
  );

  const [createOpen, setCreateOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupDescription, setNewGroupDescription] = useState('');
  const [newGroupJoinSelf, setNewGroupJoinSelf] = useState(true);
  const [creating, setCreating] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // Client-side filter — the /groups response is already scoped to
  // "groups visible to me", so the list is bounded and a simple
  // substring match on a few text fields covers the use case without
  // a server round-trip.
  const [search, setSearch] = useState('');
  const filteredGroups = React.useMemo(() => {
    if (!groups) return groups;
    const q = search.trim().toLowerCase();
    if (!q) return groups;
    return groups.filter((g) =>
      [g.name, g.displayName, g.description]
        .filter(Boolean)
        .some((s) => s!.toLowerCase().includes(q))
    );
  }, [groups, search]);

  // Caller info for UI gating: hide management actions (Delete, Create
  // Group) we know will fail. Server-side checks remain authoritative;
  // these gates just keep us from rendering buttons that 403. SWR keys
  // 'me' and 'getUser' are reused across the app, so no extra fetches.
  const { data: me } = useSWR<Me | undefined>('me', () => MeService.get());
  const { data: whoami } = useSWR('getUser', getUser);
  const isSystemAdmin = whoami?.authenticated && whoami.role === 'admin';
  // Group creation requires admin or user-admin server-side. We don't
  // have a public "user-admin" signal from /me/whoami, so for the UI
  // we restrict the Create button to system admins (the common case);
  // user-admins can still POST /groups via the CLI/API.
  const canCreateGroups = !!isSystemAdmin;

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
                name: newGroupName,
                description: newGroupDescription,
              }),
            })
          ),
        'Error Creating Group',
        dispatch
      );
      if (response?.ok) {
        // Optionally add the creator as a member so they don't have to
        // immediately invite themselves. Default-on per the design
        // discussion: the typical workflow is "I make a group I will
        // also belong to." A creator who wants a group they don't sit
        // in (e.g. an admin spinning up a project group for someone
        // else) can uncheck the box.
        if (newGroupJoinSelf && me?.id) {
          const created = await response.json().catch(() => null);
          const createdId = created?.id as string | undefined;
          if (createdId) {
            // Best-effort. The creator becomes the owner server-side
            // anyway, so failing to also add them as a member is not
            // fatal — log and move on.
            await alertOnError(
              async () =>
                fetchApi(async () =>
                  fetch(`/api/v1.0/groups/${createdId}/members`, {
                    method: 'POST',
                    body: JSON.stringify({ userId: me.id }),
                  })
                ),
              'Group created, but adding you as a member failed',
              dispatch
            );
          }
        }
        await mutate();
        setNewGroupName('');
        setNewGroupDescription('');
        setNewGroupJoinSelf(true);
        setCreateOpen(false);
      }
    } finally {
      setCreating(false);
    }
  };

  // ConfirmButton calls onConfirm on the second click; the first click
  // expands it inline into a confirm/cancel pair. No window-level modal.
  const handleDeleteGroup = async (id: string) => {
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

  return (
    <AuthenticatedContent redirect>
      <Box width='100%'>
        <Box
          mb={2}
          display='flex'
          justifyContent='space-between'
          alignItems='center'
        >
          <Typography variant='h4'>Groups</Typography>
          <Box display='flex' gap={1}>
            <IconButton onClick={() => mutate()} title='Refresh'>
              <Refresh />
            </IconButton>
            {canCreateGroups && (
              <Button
                variant='contained'
                color='primary'
                onClick={() => setCreateOpen(true)}
              >
                Create Group
              </Button>
            )}
          </Box>
        </Box>

        {error && (
          <Typography color='error'>
            Failed to load groups: {error.message}
          </Typography>
        )}

        {/* Search box. Only useful when the list has more than a few
            entries; we still render unconditionally for muscle-memory. */}
        {groups && groups.length > 0 && (
          <TextField
            size='small'
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder='Filter by name, display name, or description'
            sx={{ mb: 2, width: '100%', maxWidth: 480 }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position='start'>
                    <Search fontSize='small' />
                  </InputAdornment>
                ),
                endAdornment: search ? (
                  <InputAdornment position='end'>
                    <IconButton
                      size='small'
                      aria-label='Clear search'
                      onClick={() => setSearch('')}
                    >
                      <Clear fontSize='small' />
                    </IconButton>
                  </InputAdornment>
                ) : null,
              },
            }}
          />
        )}

        {/* Empty-state copy is split because the most common reason a
            user sees an empty list isn't "no groups exist" — it's
            "you're not in any groups yet" (the listing is scoped to
            the caller for non-admins). The CTA also differs: only an
            admin or user-admin can create one; everyone else needs an
            invite link. */}
        {groups && groups.length === 0 && (
          <EmptyGroupList
            isAdmin={!!isSystemAdmin}
            canCreate={canCreateGroups}
            onCreate={() => setCreateOpen(true)}
          />
        )}
        {groups &&
          groups.length > 0 &&
          filteredGroups &&
          filteredGroups.length === 0 && (
            <Typography color='text.secondary'>
              No groups match &ldquo;{search}&rdquo;.
            </Typography>
          )}

        {(filteredGroups || []).map((g) => (
          <Accordion
            key={g.id}
            expanded={expandedId === g.id}
            onChange={(_, isExpanded) =>
              setExpandedId(isExpanded ? g.id : null)
            }
          >
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Box
                width='100%'
                display='flex'
                alignItems='center'
                justifyContent='space-between'
                gap={2}
              >
                <Box minWidth={0} flexGrow={1}>
                  <Typography variant='h6' sx={{ wordBreak: 'break-word' }}>
                    {g.name}
                  </Typography>
                  <Box
                    display='flex'
                    alignItems='center'
                    gap={1}
                    flexWrap='wrap'
                    color='text.secondary'
                  >
                    <Typography variant='caption' component='span'>
                      Owner:
                    </Typography>
                    <UserPill card={g.ownerUser} id={g.ownerId} />
                    {g.adminId && (
                      <>
                        <Typography variant='caption' component='span'>
                          ·
                        </Typography>
                        <Typography variant='caption' component='span'>
                          Admin:
                        </Typography>
                        {g.adminType === 'user' ? (
                          <UserPill card={g.adminUser} id={g.adminId} />
                        ) : (
                          <Typography variant='body2' component='span'>
                            {g.adminGroup?.name ?? g.adminId} (group)
                          </Typography>
                        )}
                      </>
                    )}
                  </Box>
                </Box>
                <Box
                  display='flex'
                  gap={0.5}
                  alignItems='center'
                  // Stop propagation so action clicks don't toggle the accordion.
                  onClick={(e) => e.stopPropagation()}
                  onFocus={(e) => e.stopPropagation()}
                >
                  <IconButton
                    size='small'
                    component={Link}
                    href={`/groups/view/?id=${g.id}`}
                    title='Open full page'
                    aria-label='Open full page'
                  >
                    <OpenInNew fontSize='small' />
                  </IconButton>
                  {/* Delete is owner-only (or system admin) on the
                      backend (database.DeleteGroup uses
                      isGroupOwnerOnly). Hide for everyone else so we
                      don't render a button that 403s. */}
                  {(isSystemAdmin || (me && g.ownerId === me.id)) && (
                    // Inline confirmation — first click expands the
                    // button into "Confirm? × ✓" rather than popping
                    // a window.confirm modal. We stop propagation so
                    // the surrounding accordion summary doesn't toggle
                    // when the user clicks either the button or its
                    // expanded confirm/cancel pair.
                    <Box onClick={(e) => e.stopPropagation()}>
                      <ConfirmButton
                        size='small'
                        color='error'
                        onConfirm={() => handleDeleteGroup(g.id)}
                        title={`Delete group "${g.name}"`}
                        aria-label={`Delete group "${g.name}"`}
                      >
                        <Delete fontSize='small' />
                      </ConfirmButton>
                    </Box>
                  )}
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <GroupDetail
                group={g}
                visibleGroups={groups || []}
                onChanged={() => mutate()}
              />
            </AccordionDetails>
          </Accordion>
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
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label='Group Name'
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              required
              fullWidth
            />
            <TextField
              label='Description'
              value={newGroupDescription}
              onChange={(e) => setNewGroupDescription(e.target.value)}
              fullWidth
              multiline
              rows={2}
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={newGroupJoinSelf}
                  onChange={(e) => setNewGroupJoinSelf(e.target.checked)}
                />
              }
              label='Add me as a member of this group'
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button
            variant='contained'
            onClick={handleCreateGroup}
            disabled={creating || !newGroupName}
          >
            {creating ? 'Creating…' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </AuthenticatedContent>
  );
};

// EmptyGroupList renders the right copy for the "you can see zero
// groups" case based on the caller's role. For an admin the list
// being empty really does mean the federation has no groups, so the
// CTA is "create one." For everyone else it almost always means
// "you're not in any groups yet" — and the way to fix that isn't to
// create one (most can't), it's to ask whoever runs your group for
// an invite link.
const EmptyGroupList: React.FC<{
  isAdmin: boolean;
  canCreate: boolean;
  onCreate: () => void;
}> = ({ isAdmin, canCreate, onCreate }) => {
  if (isAdmin) {
    return (
      <Box
        sx={{
          p: 4,
          border: '1px dashed',
          borderColor: 'divider',
          borderRadius: 1,
          textAlign: 'center',
        }}
      >
        <Typography variant='h6' sx={{ mb: 1 }}>
          No groups exist yet
        </Typography>
        <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
          Create the first group to start organising users and access.
        </Typography>
        {canCreate && (
          <Button variant='contained' onClick={onCreate}>
            Create Group
          </Button>
        )}
      </Box>
    );
  }
  return (
    <Box
      sx={{
        p: 4,
        border: '1px dashed',
        borderColor: 'divider',
        borderRadius: 1,
      }}
    >
      <Typography variant='h6' sx={{ mb: 1 }}>
        You&rsquo;re not a member of any groups yet
      </Typography>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 1 }}>
        Groups bundle users together so the system can grant access by
        membership rather than per-user. You join one by redeeming an
        invite link from whoever runs the group — typically a project
        lead or admin.
      </Typography>
      <Typography variant='body2' color='text.secondary'>
        If you&rsquo;re expecting to be in a group, ask its owner or
        administrator to send you an invite link.
      </Typography>
    </Box>
  );
};

export default Page;
