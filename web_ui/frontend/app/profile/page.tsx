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
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  Paper,
  Skeleton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import LogoutIcon from '@mui/icons-material/Logout';
import LinkOffIcon from '@mui/icons-material/LinkOff';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import Link from 'next/link';
import useSWR from 'swr';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { Me, MeService, MyGroup } from '@/helpers/api';
import { UserIdentity } from '@/types';

// Min visible "Saving..." duration so it doesn't flash by on fast responses.
const MIN_SAVING_MS = 600;
const ensureMinDuration = async (start: number) => {
  const elapsed = Date.now() - start;
  if (elapsed < MIN_SAVING_MS) {
    await new Promise((r) => setTimeout(r, MIN_SAVING_MS - elapsed));
  }
};

// isInternalIdentity reports whether the caller's *primary* (sub, issuer)
// is the internal one — the one we use to issue cookies for accounts
// with locally-stored passwords. Per the design contract, on the
// internal issuer the sub equals the username (CreateLocalUser sets
// it that way and RenameUser keeps them in lockstep). So we can
// detect "this is the internal identity" without reading server
// config: the sub matches the username. Anything else is an external
// IdP-issued identity worth showing in the linked-identities list.
const isInternalIdentity = (me: Me) => me.sub === me.username;

const Page = () => {
  return (
    // Any logged-in user (no role filter); not-logged-in users get
    // redirected to login. Logged-in-but-wrong-role isn't possible here
    // since we don't pass allowedRoles.
    <AuthenticatedContent redirect>
      <ProfileContent />
    </AuthenticatedContent>
  );
};

const ProfileContent = () => {
  const dispatch = useContext(AlertDispatchContext);

  const {
    data: me,
    isLoading: meLoading,
    mutate: mutateMe,
  } = useSWR<Me | undefined>('me', () =>
    alertOnError(MeService.get, 'Failed to load your account', dispatch)
  );

  const {
    data: groups,
    isLoading: groupsLoading,
    mutate: mutateGroups,
  } = useSWR<MyGroup[] | undefined>('me/groups', () =>
    alertOnError(MeService.getGroups, 'Failed to load your groups', dispatch)
  );

  const {
    data: identities,
    isLoading: identitiesLoading,
    mutate: mutateIdentities,
  } = useSWR<UserIdentity[] | undefined>('me/identities', () =>
    alertOnError(
      MeService.getIdentities,
      'Failed to load your linked identities',
      dispatch
    )
  );

  return (
    <Stack spacing={3} sx={{ maxWidth: 760 }}>
      <Typography variant='h4'>Your account</Typography>

      {meLoading || !me ? (
        <Skeleton variant='rounded' height={260} />
      ) : (
        <AccountCard me={me} onUpdated={mutateMe} />
      )}

      <Typography variant='h5'>Linked identities</Typography>
      {meLoading || identitiesLoading || !me ? (
        <Skeleton variant='rounded' height={120} />
      ) : (
        <IdentitiesCard
          me={me}
          identities={identities ?? []}
          onChanged={mutateIdentities}
        />
      )}

      <Typography variant='h5'>Your groups</Typography>
      {groupsLoading || !groups ? (
        <Skeleton variant='rounded' height={120} />
      ) : (
        <GroupList groups={groups} onChanged={mutateGroups} />
      )}
    </Stack>
  );
};

// AccountCard is the username + display-name + password panel. We
// deliberately do NOT surface the user's primary (sub, issuer) here when
// it's the internal identity (sub == username, issuer == this server) —
// that pair is an implementation detail of password login. For OIDC
// users, the primary identity is shown in the IdentitiesCard below
// rather than mixed in with editable account fields.
const AccountCard: React.FC<{
  me: Me;
  onUpdated: () => Promise<Me | undefined> | void;
}> = ({ me, onUpdated }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [displayName, setDisplayName] = useState(me.displayName ?? '');
  const [saving, setSaving] = useState(false);

  const dirty = displayName !== (me.displayName ?? '');

  const saveDisplayName = async () => {
    setSaving(true);
    const start = Date.now();
    const ok = await alertOnError(
      () => MeService.patch({ displayName }),
      'Failed to update display name',
      dispatch
    );
    if (ok !== undefined) {
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: 'Display name updated',
          autoHideDuration: 3000,
          alertProps: { severity: 'success' },
        },
      });
      await onUpdated();
    }
    await ensureMinDuration(start);
    setSaving(false);
  };

  return (
    <Paper variant='outlined' sx={{ p: 3 }}>
      <Stack spacing={2}>
        <ReadOnlyField label='Username' value={me.username} mono />
        <TextField
          label='Display name'
          size='small'
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          disabled={saving}
          fullWidth
          helperText='How your name is shown in the UI. Edit freely.'
        />
        <Box display='flex' justifyContent='flex-end'>
          <Button
            variant='contained'
            disabled={saving || !dirty}
            onClick={saveDisplayName}
          >
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </Box>
        <Divider />
        <PasswordIndicator me={me} />
      </Stack>
    </Paper>
  );
};

const ReadOnlyField: React.FC<{
  label: string;
  value: string;
  small?: boolean;
  mono?: boolean;
}> = ({ label, value, small, mono }) => (
  <Box>
    <Typography variant={small ? 'caption' : 'body2'} color='text.secondary'>
      {label}
    </Typography>
    <Typography
      variant={small ? 'body2' : 'body1'}
      sx={{
        fontFamily: mono || small ? 'monospace' : undefined,
        wordBreak: 'break-all',
      }}
    >
      {value || '—'}
    </Typography>
  </Box>
);

// PasswordIndicator is a read-only status row: it shows whether the
// account has a local password and explains how to (re)set it. The
// page no longer offers a self-service form for setting one — per the
// design contract, passwords are only set via an admin-issued
// password-invite link the user redeems, so OIDC-only accounts can't
// silently grow a password that outlives the IdP relationship.
const PasswordIndicator: React.FC<{ me: Me }> = ({ me }) => (
  <Box>
    <Box display='flex' alignItems='center' gap={1} mb={1}>
      <Typography variant='h6' sx={{ flexGrow: 0 }}>
        Local password
      </Typography>
      {me.hasPassword ? (
        <Chip size='small' color='success' label='set' />
      ) : (
        <Chip size='small' label='not set' />
      )}
    </Box>
    <Typography variant='body2' color='text.secondary'>
      {me.hasPassword
        ? 'You can log in with your username and password. To rotate it, ask an administrator to issue a password-set link.'
        : 'No local password is set. To enable username + password login, ask an administrator for a password-set link.'}
    </Typography>
  </Box>
);

// IdentitiesCard renders the user's primary OIDC identity (if it isn't
// the internal one — see isInternalIdentity for the rationale) plus
// every secondary identity, with self-unlink for the secondaries.
// "Linked identity" is a stable concept in the design contract; the
// internal-issuer entry would just be noise here ("you can log in
// with your password") and is replaced by the password indicator on
// the AccountCard above.
const IdentitiesCard: React.FC<{
  me: Me;
  identities: UserIdentity[];
  onChanged: () => Promise<UserIdentity[] | undefined> | void;
}> = ({ me, identities, onChanged }) => {
  const showPrimary = !isInternalIdentity(me);
  const totalRows = (showPrimary ? 1 : 0) + identities.length;

  if (totalRows === 0) {
    return (
      <Paper variant='outlined' sx={{ p: 3 }}>
        <Typography variant='body2' color='text.secondary'>
          No external identities are linked to your account. Sign in via
          OIDC to link one.
        </Typography>
      </Paper>
    );
  }

  return (
    <Paper variant='outlined'>
      <Stack divider={<Divider />}>
        {showPrimary && (
          <IdentityRow
            sub={me.sub}
            issuer={me.issuer}
            primary
          />
        )}
        {identities.map((id) => (
          <IdentityRow
            key={id.id}
            sub={id.sub}
            issuer={id.issuer}
            onUnlink={async () => {
              if (
                !window.confirm(
                  `Unlink the identity "${id.sub}" at "${id.issuer}"? You will no longer be able to log in via that identity.`
                )
              ) {
                return;
              }
              await MeService.unlinkIdentity(id.id);
              await onChanged();
            }}
          />
        ))}
      </Stack>
    </Paper>
  );
};

const IdentityRow: React.FC<{
  sub: string;
  issuer: string;
  primary?: boolean;
  onUnlink?: () => Promise<void>;
}> = ({ sub, issuer, primary, onUnlink }) => {
  const [busy, setBusy] = useState(false);
  const dispatch = useContext(AlertDispatchContext);

  return (
    <Box
      display='flex'
      alignItems='center'
      justifyContent='space-between'
      gap={2}
      px={2}
      py={1.5}
    >
      <Box minWidth={0}>
        <Box display='flex' alignItems='center' gap={1} mb={0.5}>
          <Typography
            variant='body2'
            sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
          >
            {sub}
          </Typography>
          {primary && <Chip size='small' label='primary' />}
        </Box>
        <Typography
          variant='caption'
          color='text.secondary'
          sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
        >
          at {issuer}
        </Typography>
      </Box>
      {onUnlink && (
        <Tooltip title='Unlink this identity'>
          <span>
            <IconButton
              color='warning'
              disabled={busy}
              aria-label='Unlink identity'
              onClick={async () => {
                setBusy(true);
                await alertOnError(
                  onUnlink,
                  'Failed to unlink identity',
                  dispatch
                );
                setBusy(false);
              }}
            >
              <LinkOffIcon fontSize='small' />
            </IconButton>
          </span>
        </Tooltip>
      )}
      {primary && (
        <Tooltip title='Your primary identity is admin-managed and cannot be unlinked here.'>
          <Chip size='small' variant='outlined' label='managed by admin' />
        </Tooltip>
      )}
    </Box>
  );
};

const GroupList: React.FC<{
  groups: MyGroup[];
  onChanged: () => Promise<MyGroup[] | undefined> | void;
}> = ({ groups, onChanged }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [leavingId, setLeavingId] = useState<string | null>(null);

  const leave = async (g: MyGroup) => {
    setLeavingId(g.id);
    const ok = await alertOnError(
      () => MeService.leaveGroup(g.id),
      'Failed to leave group',
      dispatch
    );
    if (ok !== undefined) {
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: `Left ${g.name}`,
          autoHideDuration: 3000,
          alertProps: { severity: 'success' },
        },
      });
      await onChanged();
    }
    setLeavingId(null);
    setConfirmingId(null);
  };

  if (groups.length === 0) {
    return (
      <Paper variant='outlined' sx={{ p: 3 }}>
        <Typography color='text.secondary'>
          You are not a member of any groups.
        </Typography>
      </Paper>
    );
  }

  return (
    <Paper variant='outlined'>
      <Stack divider={<Divider />}>
        {groups.map((g) => {
          const confirming = confirmingId === g.id;
          const leaving = leavingId === g.id;
          return (
            <Box
              key={g.id}
              display='flex'
              alignItems='center'
              justifyContent='space-between'
              px={2}
              py={1.5}
              gap={2}
            >
              {/* Group name links to the group's own page (admin/owner
                  controls there, read-only view for plain members). The
                  whole-row click target keeps the leave action explicit. */}
              <Box minWidth={0} sx={{ flexGrow: 1 }}>
                <Box display='flex' alignItems='center' gap={1}>
                  <Link
                    href={`/groups/view/?id=${encodeURIComponent(g.id)}`}
                    style={{ textDecoration: 'none', color: 'inherit' }}
                  >
                    <Typography
                      variant='body1'
                      sx={{
                        fontWeight: 500,
                        '&:hover': { textDecoration: 'underline' },
                      }}
                    >
                      {g.displayName || g.name}
                    </Typography>
                  </Link>
                  <Tooltip title='Open the group page'>
                    <Link
                      href={`/groups/view/?id=${encodeURIComponent(g.id)}`}
                      style={{ display: 'inline-flex' }}
                      aria-label={`Open ${g.name}`}
                    >
                      <OpenInNewIcon
                        fontSize='inherit'
                        color='action'
                      />
                    </Link>
                  </Tooltip>
                </Box>
                {g.displayName && g.displayName !== g.name && (
                  <Typography variant='caption' color='text.secondary'>
                    {g.name}
                  </Typography>
                )}
                {g.description && (
                  <Typography
                    variant='body2'
                    color='text.secondary'
                    sx={{ mt: 0.25 }}
                  >
                    {g.description}
                  </Typography>
                )}
              </Box>
              {confirming ? (
                <Stack direction='row' spacing={1}>
                  <Button
                    size='small'
                    onClick={() => setConfirmingId(null)}
                    disabled={leaving}
                  >
                    Cancel
                  </Button>
                  <Button
                    size='small'
                    variant='contained'
                    color='warning'
                    startIcon={<LogoutIcon />}
                    disabled={leaving}
                    onClick={() => leave(g)}
                  >
                    {leaving ? 'Leaving...' : `Confirm leave`}
                  </Button>
                </Stack>
              ) : (
                <Button
                  size='small'
                  variant='outlined'
                  color='warning'
                  startIcon={<LogoutIcon />}
                  onClick={() => setConfirmingId(g.id)}
                  aria-label={`leave ${g.name}`}
                >
                  Leave
                </Button>
              )}
            </Box>
          );
        })}
      </Stack>
    </Paper>
  );
};

export default Page;
