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

import React, { useContext, useEffect, useState } from 'react';
import {
  Autocomplete,
  Box,
  Button,
  IconButton,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from '@mui/material';
import { Edit as EditIcon } from '@mui/icons-material';
import { AdminType, Group, User } from '@/types';
import UserPill, { formatUserPill } from './UserPill';
import { fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';

interface InlineAdminEditProps {
  group: Group;
  // Other groups the caller can see, used as the candidate set when the
  // admin is a group. Pass an empty array to disable the group option.
  visibleGroups: Group[];
  onChanged: () => void;
  /** Whether the caller may actually change the administrator. Same
   * rule as ownership transfer: only the owner (or a system admin) can.
   * When false we render read-only — no pencil affordance — to keep
   * group-admin users from clicking through to a guaranteed 403. */
  canEdit: boolean;
}

type AdminKind = 'none' | 'user' | 'group';

// InlineAdminEdit shows the current group administrator and offers an
// inline editor (toggle: None / User / Group, plus the appropriate picker).
// Save commits via PUT /groups/:id/ownership; Cancel reverts the form.
const InlineAdminEdit: React.FC<InlineAdminEditProps> = ({
  group,
  visibleGroups,
  onChanged,
  canEdit,
}) => {
  const dispatch = useContext(AlertDispatchContext);
  const [editing, setEditing] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [kind, setKind] = useState<AdminKind>('none');
  const [candidateUser, setCandidateUser] = useState<User | null>(null);
  const [candidateGroup, setCandidateGroup] = useState<Group | null>(null);

  // Initialize form to reflect current state when entering edit mode.
  useEffect(() => {
    if (!editing) return;
    if (group.adminId && group.adminType === 'user') {
      setKind('user');
      // group.members is GroupMember[]; the actual User is nested.
      const match = (group.members || []).find(
        (m) => m.userId === group.adminId
      );
      setCandidateUser(match ? match.user : null);
      setCandidateGroup(null);
    } else if (group.adminId && group.adminType === 'group') {
      setKind('group');
      const match = visibleGroups.find((g) => g.id === group.adminId);
      setCandidateGroup(match ?? null);
      setCandidateUser(null);
    } else {
      setKind('none');
      setCandidateUser(null);
      setCandidateGroup(null);
    }
  }, [editing, group, visibleGroups]);

  const cancel = () => setEditing(false);

  const submit = async () => {
    let body: { adminId: string; adminType: AdminType | '' };
    if (kind === 'user') {
      if (!candidateUser) return;
      body = { adminId: candidateUser.id, adminType: 'user' };
    } else if (kind === 'group') {
      if (!candidateGroup) return;
      body = { adminId: candidateGroup.id, adminType: 'group' };
    } else {
      body = { adminId: '', adminType: '' };
    }
    setSubmitting(true);
    const ok = await alertOnError(
      async () =>
        fetchApi(async () =>
          fetch(`/api/v1.0/groups/${group.id}/ownership`, {
            method: 'PUT',
            body: JSON.stringify(body),
          })
        ),
      'Failed to update group administrator',
      dispatch
    );
    setSubmitting(false);
    if (ok) {
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: 'Group administrator updated',
          autoHideDuration: 3000,
          alertProps: { severity: 'success' },
        },
      });
      cancel();
      onChanged();
    }
  };

  if (!editing) {
    return (
      <Box display='flex' alignItems='center' gap={1} flexWrap='wrap'>
        <Typography variant='body2' color='text.secondary'>
          Administrator:
        </Typography>
        {!group.adminId && (
          <Typography variant='body2' color='text.secondary' fontStyle='italic'>
            (none)
          </Typography>
        )}
        {group.adminId && group.adminType === 'user' && (
          <>
            <Typography variant='caption' color='text.secondary'>
              user
            </Typography>
            <UserPill card={group.adminUser} id={group.adminId} emphasized />
          </>
        )}
        {group.adminId && group.adminType === 'group' && (
          <>
            <Typography variant='caption' color='text.secondary'>
              group
            </Typography>
            <Typography variant='body2' fontWeight={600}>
              {group.adminGroup?.name ?? group.adminId}
            </Typography>
          </>
        )}
        {canEdit && (
          <IconButton
            size='small'
            aria-label='Edit group administrator'
            title='Edit group administrator'
            onClick={() => setEditing(true)}
          >
            <EditIcon fontSize='small' />
          </IconButton>
        )}
      </Box>
    );
  }

  return (
    <Stack spacing={1}>
      <Typography variant='body2' color='text.secondary'>
        Administrator:
      </Typography>
      <ToggleButtonGroup
        value={kind}
        exclusive
        size='small'
        onChange={(_, v) => v && setKind(v as AdminKind)}
      >
        <ToggleButton value='none'>None</ToggleButton>
        <ToggleButton value='user'>User</ToggleButton>
        <ToggleButton value='group'>Group</ToggleButton>
      </ToggleButtonGroup>
      {kind === 'user' && (
        <Autocomplete
          size='small'
          // Autocomplete options must be User[], so project the
          // GroupMember[] members through `.user` here.
          options={(group.members || []).map((m) => m.user)}
          getOptionLabel={(u) => formatUserPill(u).primary}
          value={candidateUser}
          onChange={(_, v) => setCandidateUser(v)}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          noOptionsText='No members yet. Add a member first or pick a group instead.'
          renderInput={(params) => (
            <TextField {...params} placeholder='Select a member' />
          )}
        />
      )}
      {kind === 'group' && (
        <Autocomplete
          size='small'
          options={visibleGroups.filter((g) => g.id !== group.id)}
          getOptionLabel={(g) => g.name}
          value={candidateGroup}
          onChange={(_, v) => setCandidateGroup(v)}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          noOptionsText='No other groups visible to you.'
          renderInput={(params) => (
            <TextField {...params} placeholder='Select a group' />
          )}
        />
      )}
      <Box display='flex' gap={1}>
        <Button
          size='small'
          variant='contained'
          onClick={submit}
          disabled={
            submitting ||
            (kind === 'user' && !candidateUser) ||
            (kind === 'group' && !candidateGroup)
          }
        >
          Save
        </Button>
        <Button size='small' onClick={cancel} disabled={submitting}>
          Cancel
        </Button>
      </Box>
    </Stack>
  );
};

export default InlineAdminEdit;
