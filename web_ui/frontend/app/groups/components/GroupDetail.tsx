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
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Divider,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  GroupAdd as GroupAddIcon,
  PersonAdd as PersonAddIcon,
  PersonRemove as PersonRemoveIcon,
} from '@mui/icons-material';
import ConfirmButton from '@chtc/web-components/ConfirmButton';
import useSWR from 'swr';
import { Group } from '@/types';
import {
  GroupScopeGrant,
  Me,
  MeService,
  MyGroup,
  ScopeCatalogEntry,
  ScopeService,
  UserService,
} from '@/helpers/api';
// User from the API helper rather than @/types: UserService.getAll()
// returns the slim shape (no status / updatedAt). UserPill / formatUserPill
// only need username + displayName, which both shapes carry.
import type { User } from '@/helpers/api/User/types';
import { getUser } from '@/helpers/login';
import { fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import UserPill from './UserPill';
import InlineOwnerEdit from './InlineOwnerEdit';
import InlineAdminEdit from './InlineAdminEdit';
import InviteLinksPanel from './InviteLinksPanel';

interface GroupDetailProps {
  group: Group;
  // Other groups the caller can see — passed in (not fetched here) so the
  // list page can pass its already-loaded /groups response and the full
  // page can fetch separately. An empty array disables "admin = group".
  visibleGroups: Group[];
  /** Triggered after any inline edit succeeds. */
  onChanged: () => void;
}

// canManageGroup decides whether to show management controls that
// owners *or* group admins are allowed to drive (member add/remove,
// invite links). The same checks run server-side in
// database.CanManageGroup; this is purely a UI gate to avoid
// presenting controls that will 403. Conservative: when in doubt (e.g.
// /me/groups hasn't loaded yet) we deny — better to flash a hidden
// control briefly than to show one that will fail.
function canManageGroup(
  group: Group,
  me: Me | undefined,
  myGroups: MyGroup[] | undefined,
  role: string | null | undefined
): boolean {
  if (role === 'admin') return true; // system admins can do anything
  if (!me) return false;
  if (group.ownerId === me.id) return true;
  if (group.adminType === 'user' && group.adminId === me.id) return true;
  if (
    group.adminType === 'group' &&
    group.adminId &&
    (myGroups || []).some((g) => g.id === group.adminId)
  ) {
    return true;
  }
  return false;
}

// canTransferOwnership is the stricter check used for ownership /
// administrator reassignment. The design contract gives those exclusively
// to the *owner* (or a system admin). Group admins can run the group
// day-to-day but cannot decide who owns or administers it; the UI hides
// the pencil affordance from them so they aren't tempted to click into
// a guaranteed 403.
function canTransferOwnership(
  group: Group,
  me: Me | undefined,
  role: string | null | undefined
): boolean {
  if (role === 'admin') return true;
  if (!me) return false;
  return group.ownerId === me.id;
}

// GroupDetail is the canonical group view: ownership, admin, members, and
// invite links. It is rendered inside the accordion on the list page AND as
// the body of /groups/view/?id=… (the project ships a static export,
// so per-group pages use a query-string id rather than a dynamic-segment
// route — see the comment on view/page.tsx). All write actions are
// inline (no dialogs) — edit affordances appear next to each settable
// field. Read-only fields (createdBy, timestamps) are shown as text.
const GroupDetail: React.FC<GroupDetailProps> = ({
  group,
  visibleGroups,
  onChanged,
}) => {
  // SWR keys 'me', 'me/groups', 'getUser' are reused across the app, so
  // these fetches share the same cache entries as the profile page and
  // the user-menu — no extra round-trips per group card on the list.
  const { data: me } = useSWR<Me | undefined>('me', () => MeService.get());
  const { data: myGroups } = useSWR<MyGroup[] | undefined>('me/groups', () =>
    MeService.getGroups()
  );
  const { data: whoami } = useSWR('getUser', getUser);

  const role = whoami?.authenticated ? whoami.role : null;
  const canManage = canManageGroup(group, me, myGroups, role);
  const canEditOwnership = canTransferOwnership(group, me, role);
  // The caller is already a member if they appear in group.members.
  // (Owners and group admins are NOT necessarily members — a user can
  // own/administer a group without being listed in its membership; we
  // surface a "Join this group" affordance for that case below.)
  const isMember = !!(
    me && (group.members || []).some((m) => m.userId === me.id)
  );

  return (
    <Stack spacing={2}>
      {group.description && (
        <Typography variant='body2'>{group.description}</Typography>
      )}

      <Box>
        <Typography variant='subtitle1' sx={{ mb: 0.5 }}>
          Ownership
        </Typography>
        <Stack spacing={1.5}>
          {canManage ? (
            <>
              <InlineOwnerEdit
                group={group}
                onChanged={onChanged}
                canEdit={canEditOwnership}
              />
              <InlineAdminEdit
                group={group}
                visibleGroups={visibleGroups}
                onChanged={onChanged}
                canEdit={canEditOwnership}
              />
            </>
          ) : (
            // Read-only view for members who can't manage — surfaces
            // the same information without the edit affordances.
            <>
              <Box display='flex' alignItems='center' gap={1}>
                <Typography variant='body2' color='text.secondary'>
                  Owner:
                </Typography>
                <UserPill
                  card={group.ownerUser}
                  id={group.ownerId}
                  emphasized
                />
              </Box>
              {group.adminId && (
                <Box display='flex' alignItems='center' gap={1}>
                  <Typography variant='body2' color='text.secondary'>
                    Administrator:
                  </Typography>
                  {group.adminType === 'user' ? (
                    <UserPill
                      card={group.adminUser}
                      id={group.adminId}
                      emphasized
                    />
                  ) : (
                    <Typography variant='body2' fontWeight={600}>
                      {group.adminGroup?.name ?? group.adminId} (group)
                    </Typography>
                  )}
                </Box>
              )}
            </>
          )}
          <Box display='flex' alignItems='center' gap={1}>
            <Typography variant='body2' color='text.secondary'>
              Created by:
            </Typography>
            <UserPill card={group.createdByUser} id={group.createdBy} />
            <Typography variant='caption' color='text.secondary'>
              on {new Date(group.createdAt).toLocaleDateString()}
            </Typography>
          </Box>
        </Stack>
      </Box>

      <Divider />

      <Box>
        <Box display='flex' alignItems='center' gap={1} mb={1}>
          <Typography variant='subtitle1'>Members</Typography>
          <Chip size='small' label={group.members?.length ?? 0} />
          {/* Join-self button. Surfaced for owners/admins who manage the
              group but aren't yet listed as members — typical for a
              freshly-created group when the creator skipped the
              "add me as a member" checkbox, or for a group admin
              brought in via the group_admin / admin-group path. The
              backend POST /groups/:id/members endpoint already accepts
              an owner/admin adding any user including themselves, so
              no extra route is needed. */}
          {canManage && me && !isMember && (
            <JoinSelfButton
              groupId={group.id}
              userId={me.id}
              onChanged={onChanged}
            />
          )}
          {/* "Conscript" button — pick any user from the full user
              table and add them to this group. Site-admin-only at the
              UI level because the picker uses UserService.getAll(),
              which is admin-walled server-side. Group owners/admins
              who aren't site admins still have JoinSelfButton (above)
              for self-add and the invite-link flow for everyone else.
              The backend route already accepts the action — we're
              just exposing it. */}
          {role === 'admin' && (
            <AddMemberButton group={group} onChanged={onChanged} />
          )}
        </Box>
        {!group.members || group.members.length === 0 ? (
          <Typography variant='body2' color='text.secondary'>
            No members yet.
          </Typography>
        ) : (
          <List dense disablePadding>
            {group.members.map((m) => (
              <ListItem
                key={m.userId}
                disableGutters
                secondaryAction={
                  // Group owners and admins (and system admins) may
                  // remove members — including the owner row. The
                  // backend treats "membership" and "ownership" as
                  // independent: removing an owner from group_members
                  // does NOT relinquish their ownership of the group.
                  // (The self-leave path in LeaveGroup() blocks an
                  // owner from quitting their own group; that's a
                  // different, narrower guard.) Showing the button
                  // for the owner row lets admins prune the
                  // membership table without first having to
                  // transfer ownership.
                  canManage ? (
                    <RemoveMemberButton
                      groupId={group.id}
                      userId={m.userId}
                      label={m.user?.username || m.userId}
                      onChanged={onChanged}
                    />
                  ) : null
                }
              >
                <ListItemText
                  primary={<UserPill card={m.user} />}
                  secondary={m.userId === group.ownerId ? 'owner' : null}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Box>

      {/* Invite-link management is owner/admin-only — server enforces it
          (and would 403 the list endpoint) so we don't even surface the
          panel for plain members. */}
      {canManage && (
        <>
          <Divider />
          <InviteLinksPanel groupId={group.id} />
        </>
      )}

      {/* Scope grants on the group itself. Granting a scope to a group
          transitively grants it to every member (and to OIDC-asserted
          members), so granting/revoking is system-admin-only at both
          the UI and the backend. canManage's permissive set (group
          owners, group admins) is wider than what the server allows
          here, so we use the explicit role check instead. */}
      {role === 'admin' && (
        <>
          <Divider />
          <GroupScopesSection groupId={group.id} />
        </>
      )}
    </Stack>
  );
};

// JoinSelfButton lets an owner/admin add themselves as a member of a
// group they manage but don't yet sit in. Same endpoint as adding any
// other member — there's no separate "I'm joining" route — so the
// server-side authz path is well-trodden.
const JoinSelfButton: React.FC<{
  groupId: string;
  userId: string;
  onChanged: () => void;
}> = ({ groupId, userId, onChanged }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState(false);
  return (
    <Button
      size='small'
      variant='outlined'
      startIcon={<PersonAddIcon fontSize='small' />}
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        const ok = await alertOnError(
          async () =>
            fetchApi(async () =>
              fetch(`/api/v1.0/groups/${groupId}/members`, {
                method: 'POST',
                body: JSON.stringify({ userId }),
              })
            ),
          'Failed to add yourself to the group',
          dispatch
        );
        setBusy(false);
        if (ok) onChanged();
      }}
    >
      Join this group
    </Button>
  );
};

// RemoveMemberButton removes a member from a group. Owner/admin/system-
// admin only — server-side enforced. Uses the inline-confirm
// ConfirmButton pattern (first click expands into "are you sure?", a
// second click commits) instead of a modal dialog.
const RemoveMemberButton: React.FC<{
  groupId: string;
  userId: string;
  label: string;
  onChanged: () => void;
}> = ({ groupId, userId, label, onChanged }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState(false);
  return (
    <ConfirmButton
      size='small'
      color='warning'
      aria-label={`Remove ${label} from this group`}
      title={`Remove ${label}`}
      disabled={busy}
      onConfirm={async () => {
        setBusy(true);
        const ok = await alertOnError(
          async () =>
            fetchApi(async () =>
              fetch(`/api/v1.0/groups/${groupId}/members/${userId}`, {
                method: 'DELETE',
              })
            ),
          'Failed to remove member',
          dispatch
        );
        setBusy(false);
        if (ok) onChanged();
      }}
    >
      <PersonRemoveIcon fontSize='small' />
    </ConfirmButton>
  );
};

// GroupScopesSection lists the scopes granted to this group (every
// member transitively inherits them) and offers a picker to add more.
// System-admin only at the UI level — the backend rejects grants /
// revokes from anyone else, so we don't surface the controls.
const GroupScopesSection: React.FC<{ groupId: string }> = ({ groupId }) => {
  const dispatch = useContext(AlertDispatchContext);
  const { data: grants, mutate } = useSWR<GroupScopeGrant[] | undefined>(
    `groups/${groupId}/scopes`,
    () =>
      alertOnError(
        () => ScopeService.listGroup(groupId),
        'Failed to load group scopes',
        dispatch
      ),
    { fallbackData: [] }
  );
  const { data: catalog } = useSWR<ScopeCatalogEntry[] | undefined>(
    'scopes-catalog',
    () =>
      alertOnError(
        ScopeService.catalog,
        'Failed to load scope catalog',
        dispatch
      ),
    { fallbackData: [] }
  );
  const [picker, setPicker] = useState<ScopeCatalogEntry | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const grantedNames = new Set((grants || []).map((g) => g.scope));
  // Keep the FULL catalog entries (not just names) so the picker can
  // render the description alongside each scope name.
  const candidates: ScopeCatalogEntry[] = (catalog || []).filter(
    (c) => !grantedNames.has(c.name)
  );

  // Description-by-name lookup so the granted-scope chips can carry a
  // tooltip without each chip needing the full catalog separately.
  const describeScope = (name: string): string =>
    (catalog || []).find((c) => c.name === name)?.description ?? '';

  const grant = async () => {
    if (!picker) return;
    const scopeName = picker.name;
    setBusy(`grant:${scopeName}`);
    let success = false;
    try {
      await alertOnError(
        () => ScopeService.grantGroup(groupId, scopeName),
        'Failed to grant scope',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error UI */
    }
    setBusy(null);
    if (!success) return;
    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: `Granted ${scopeName}`,
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    setPicker(null);
    mutate();
  };

  const revoke = async (scope: string) => {
    setBusy(`revoke:${scope}`);
    let success = false;
    try {
      await alertOnError(
        () => ScopeService.revokeGroup(groupId, scope),
        'Failed to revoke scope',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error UI */
    }
    setBusy(null);
    if (!success) return;
    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: `Revoked ${scope}`,
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    mutate();
  };

  return (
    <Box>
      <Typography variant='subtitle1' sx={{ mb: 0.5 }}>
        Scopes
      </Typography>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Direct grants on this group. Every member of the group (database row
        member or OIDC-asserted) inherits these scopes via EffectiveScopes.
        Revoking removes the grant for all members at once.
      </Typography>
      {!grants || grants.length === 0 ? (
        <Typography variant='body2' color='text.secondary' fontStyle='italic'>
          No scopes granted to this group.
        </Typography>
      ) : (
        <Stack
          direction='row'
          spacing={1}
          flexWrap='wrap'
          rowGap={1}
          sx={{ mb: 2 }}
        >
          {grants.map((g) => {
            const desc = describeScope(g.scope);
            return (
              <Tooltip
                key={g.scope}
                title={desc || ''}
                arrow
                placement='top'
                disableHoverListener={!desc}
              >
                <Chip
                  label={g.scope}
                  variant='outlined'
                  onDelete={
                    busy === `revoke:${g.scope}`
                      ? undefined
                      : () => revoke(g.scope)
                  }
                  disabled={busy === `revoke:${g.scope}`}
                  sx={{ fontFamily: 'monospace' }}
                />
              </Tooltip>
            );
          })}
        </Stack>
      )}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <Autocomplete
          sx={{ flexGrow: 1, minWidth: 280 }}
          size='small'
          options={candidates}
          value={picker}
          onChange={(_, v) => setPicker(v)}
          getOptionLabel={(o) => o.name}
          isOptionEqualToValue={(a, b) => a.name === b.name}
          noOptionsText='Every catalog scope is already granted to this group.'
          renderOption={(props, option) => {
            // React requires `key` as a real prop, not via spread.
            const { key, ...liProps } =
              props as React.HTMLAttributes<HTMLLIElement> & {
                key?: React.Key;
              };
            return (
              <li key={key} {...liProps}>
                <Box>
                  <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
                    {option.name}
                  </Typography>
                  {option.description && (
                    <Typography
                      variant='caption'
                      color='text.secondary'
                      sx={{ display: 'block', whiteSpace: 'normal' }}
                    >
                      {option.description}
                    </Typography>
                  )}
                </Box>
              </li>
            );
          }}
          renderInput={(params) => (
            <TextField
              {...params}
              placeholder='Pick a scope to grant'
              helperText={picker?.description ?? ' '}
              slotProps={{
                formHelperText: { sx: { whiteSpace: 'normal' } },
              }}
            />
          )}
        />
        <Button
          variant='contained'
          onClick={grant}
          disabled={!picker || busy === `grant:${picker.name}`}
        >
          Grant
        </Button>
      </Stack>
    </Box>
  );
};

// AddMemberButton renders a "+ Add member" button that opens a picker
// dialog over every user the caller can list, pre-filtered to drop the
// users already in this group. Site-admin only — the picker depends on
// UserService.getAll() (admin-walled). The backend POST endpoint
// itself accepts the action regardless of how the caller is gated, so
// future work can expose this to user-admins by softening the role
// check above.
const AddMemberButton: React.FC<{
  group: Group;
  onChanged: () => void;
}> = ({ group, onChanged }) => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        size='small'
        variant='outlined'
        startIcon={<GroupAddIcon fontSize='small' />}
        onClick={() => setOpen(true)}
      >
        Add member
      </Button>
      {open && (
        <AddMemberDialog
          group={group}
          onClose={() => setOpen(false)}
          onChanged={onChanged}
        />
      )}
    </>
  );
};

const AddMemberDialog: React.FC<{
  group: Group;
  onClose: () => void;
  onChanged: () => void;
}> = ({ group, onClose, onChanged }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [users, setUsers] = useState<User[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<User | null>(null);
  const [busy, setBusy] = useState(false);

  // Fetch the user catalog once on open. We do NOT keep this in a SWR
  // cache because admins joining users to multiple groups in a row
  // benefit from a fresh list each time (a user added by an
  // intervening invite redemption should be reflected).
  useEffect(() => {
    let cancelled = false;
    UserService.getAll()
      .then((u) => {
        if (!cancelled) setUsers(u);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setLoadError(
          e instanceof Error
            ? e.message
            : 'Failed to load the user list. Site-admin privileges are required.'
        );
        setUsers([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Drop users who are already in the group. Keeps the picker scoped
  // to the action it actually performs ("add"), so the admin doesn't
  // accidentally pick someone who's already in.
  const memberIds = new Set((group.members || []).map((m) => m.userId));
  const candidates = (users || []).filter((u) => !memberIds.has(u.id));

  // Local label helper: the shared formatUserPill wants the @/types
  // User shape (with status/lastLoginAt/...) but the picker uses the
  // slim API-helper User shape. Both have username + displayName,
  // which is everything we need to render.
  const userLabel = (u: User) =>
    u.displayName && u.displayName !== u.username
      ? `${u.displayName} (${u.username})`
      : u.username;

  const submit = async () => {
    if (!selected) return;
    setBusy(true);
    let success = false;
    try {
      await alertOnError(
        async () =>
          fetchApi(async () =>
            fetch(`/api/v1.0/groups/${group.id}/members`, {
              method: 'POST',
              body: JSON.stringify({ userId: selected.id }),
            })
          ),
        'Failed to add member',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error UI */
    }
    setBusy(false);
    if (!success) return;

    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: `Added ${userLabel(selected)} to ${group.name}`,
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    onChanged();
    onClose();
  };

  return (
    <Dialog open onClose={onClose} maxWidth='sm' fullWidth>
      <DialogTitle>Add member to {group.displayName || group.name}</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          Pick any user on this server to add directly to{' '}
          <strong>{group.name}</strong>. Use this when you need to conscript a
          user without going through an invite link.
        </DialogContentText>
        {loadError && users && users.length === 0 && (
          <DialogContentText color='error' sx={{ mb: 2 }}>
            {loadError}
          </DialogContentText>
        )}
        <Autocomplete
          options={candidates}
          loading={users === null}
          getOptionLabel={userLabel}
          value={selected}
          onChange={(_, v) => setSelected(v)}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          noOptionsText={
            users && users.length === 0
              ? 'No users found.'
              : 'Every user is already in this group.'
          }
          renderInput={(params) => (
            <TextField {...params} autoFocus placeholder='Search for a user' />
          )}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant='contained'
          onClick={submit}
          disabled={!selected || busy}
        >
          {busy ? 'Adding…' : 'Add member'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default GroupDetail;
