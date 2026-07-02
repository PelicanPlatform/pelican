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
  Button,
  IconButton,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Edit as EditIcon } from '@mui/icons-material';
import { Group, User } from '@/types';
import UserPill, { formatUserPill } from './UserPill';
import { fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';

interface InlineOwnerEditProps {
  group: Group;
  onChanged: () => void;
  /** Whether the caller is allowed to actually transfer ownership. Only
   * the current owner (or a system admin) can — group admins can manage
   * the group but cannot reassign it. When false the row stays in
   * read-only mode (no pencil affordance) so the UI doesn't dangle a
   * button that will 403. Server-side enforcement still lives in
   * database.UpdateGroupOwnership / isGroupOwnerOnly. */
  canEdit: boolean;
}

// InlineOwnerEdit renders the current owner inline, with a pencil affordance
// that swaps the row for an autocomplete + Save/Cancel. The candidate set is
// the group's current member list, since a new owner must be a member (or be
// added as one first); offering a global user picker would require listing
// all users, which non-admin owners can't do.
const InlineOwnerEdit: React.FC<InlineOwnerEditProps> = ({
  group,
  onChanged,
  canEdit,
}) => {
  const dispatch = useContext(AlertDispatchContext);
  const [editing, setEditing] = useState(false);
  const [candidate, setCandidate] = useState<User | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const cancel = () => {
    setEditing(false);
    setCandidate(null);
  };

  const submit = async () => {
    if (!candidate) return;
    setSubmitting(true);
    const ok = await alertOnError(
      async () =>
        fetchApi(async () =>
          fetch(`/api/v1.0/groups/${group.id}/ownership`, {
            method: 'PUT',
            body: JSON.stringify({ ownerId: candidate.id }),
          })
        ),
      'Failed to transfer ownership',
      dispatch
    );
    setSubmitting(false);
    if (ok) {
      const { primary } = formatUserPill(candidate);
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: `Ownership transferred to ${primary}`,
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
      <Box display='flex' alignItems='center' gap={1}>
        <Typography variant='body2' color='text.secondary'>
          Owner:
        </Typography>
        <UserPill card={group.ownerUser} id={group.ownerId} emphasized />
        {canEdit && (
          <IconButton
            size='small'
            aria-label='Transfer ownership'
            title='Transfer ownership'
            onClick={() => setEditing(true)}
          >
            <EditIcon fontSize='small' />
          </IconButton>
        )}
      </Box>
    );
  }

  // Editing: only members other than the current owner are valid targets.
  // group.members is a list of GroupMember wrappers (membership + nested
  // user); we project to the User shape the Autocomplete + UserPill expect.
  const options: User[] = (group.members || [])
    .filter((m) => m.userId !== group.ownerId)
    .map((m) => m.user);

  return (
    <Stack
      direction={{ xs: 'column', sm: 'row' }}
      spacing={1}
      alignItems='flex-start'
    >
      <Typography variant='body2' color='text.secondary' sx={{ pt: 1 }}>
        Transfer to:
      </Typography>
      <Autocomplete
        sx={{ flexGrow: 1, minWidth: 240 }}
        size='small'
        options={options}
        getOptionLabel={(u) => formatUserPill(u).primary}
        value={candidate}
        onChange={(_, v) => setCandidate(v)}
        isOptionEqualToValue={(a, b) => a.id === b.id}
        noOptionsText='No other members. Add the target user as a member first.'
        renderInput={(params) => (
          <TextField {...params} placeholder='Select a member' />
        )}
      />
      <Button
        size='small'
        variant='contained'
        onClick={submit}
        disabled={!candidate || submitting}
      >
        Save
      </Button>
      <Button size='small' onClick={cancel} disabled={submitting}>
        Cancel
      </Button>
    </Stack>
  );
};

export default InlineOwnerEdit;
