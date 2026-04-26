'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import UserForm from '../components/UserForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import SettingHeader from '@/app/settings/components/SettingHeader';
import {
  Alert,
  Autocomplete,
  Box,
  Breadcrumbs,
  Button,
  Chip,
  Divider,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  InviteService,
  InviteLinkBase,
  InviteLinkCreated,
  ScopeCatalogEntry,
  ScopeService,
  UserPatch,
  UserScopeGrant,
  UserService,
} from '@/helpers/api';
import { UserIdentity } from '@/types';
import useServiceSWR from '@/hooks/useServiceSWR';
import useSWR from 'swr';
import LinkOffIcon from '@mui/icons-material/LinkOff';
import ConfirmButton from '@chtc/web-components/ConfirmButton';
import InlineConfirmButton from '@/components/InlineConfirmButton';

const Page = () => {
  const router = useRouter();
  const dispatch = useContext(AlertDispatchContext);

  const searchParams = useSearchParams();
  const userId = searchParams.get('id');

  const { data: user } = useServiceSWR(
    'Could not fetch user.',
    UserService,
    'getOne',
    [userId ?? undefined],
    { suspense: true }
  );

  const [isSubmitting, setIsSubmitting] = useState(false);

  // Ensure userId is present before rendering form
  if (!userId)
    return <Typography>Form must be opened with a defined id.</Typography>;

  return (
    <>
      <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
        <Link href={'../'}>Users</Link>
        <Typography sx={{ color: 'text.primary' }}>Edit</Typography>
      </Breadcrumbs>
      <SettingHeader title={'Edit User'} />
      <UserForm
        user={user}
        onSubmit={async (user: UserPatch) => {
          setIsSubmitting(true);
          try {
            await alertOnError(
              async () => UserService.patch(userId, user),
              'Error Editing User',
              dispatch,
              true
            );
            dispatch({
              type: 'openAlert',
              payload: {
                onClose: () => dispatch({ type: 'closeAlert' }),
                message: `Updated User`,
                autoHideDuration: 3000,
                alertProps: { severity: 'success' },
              },
            });
            router.push('../');
          } catch (error) {
            setIsSubmitting(false);
          }
        }}
        isSubmitting={isSubmitting}
      />
      <Divider sx={{ my: 4 }} />
      <PasswordSection userId={userId} hasPassword={user?.hasPassword} />
      <Divider sx={{ my: 4 }} />
      <AUPSection
        userId={userId}
        aupVersion={user?.aupVersion}
        aupAgreedAt={user?.aupAgreedAt}
      />
      <Divider sx={{ my: 4 }} />
      <ScopesSection userId={userId} />
      <Divider sx={{ my: 4 }} />
      <IdentitiesSection userId={userId} />
    </>
  );
};

// AUPSection shows the user's current AUP acceptance state and
// surfaces an admin-only "Clear acceptance" action that forces this
// single user back through the AUP workflow on their next page load.
// Distinct from rotating the active AUP itself (which would re-prompt
// every user on the server).
const AUPSection: React.FC<{
  userId: string;
  aupVersion?: string;
  aupAgreedAt?: string | null;
}> = ({ userId, aupVersion, aupAgreedAt }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState(false);
  const accepted = !!aupVersion;

  const onClick = async () => {
    setBusy(true);
    let success = false;
    try {
      await alertOnError(
        () => UserService.clearAUP(userId),
        'Failed to clear AUP acceptance',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error */
    }
    setBusy(false);
    if (!success) return;

    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: 'AUP acceptance cleared',
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    // Refresh the user record so the chip flips to "no acceptance".
    window.location.reload();
  };

  return (
    <Box>
      <Typography variant='h6' sx={{ mb: 1 }}>
        Acceptable Use Policy
      </Typography>
      <Box display='flex' alignItems='center' gap={1} sx={{ mb: 2 }}>
        <Typography variant='body2'>Status:</Typography>
        {accepted ? (
          <Chip
            size='small'
            color='success'
            label={`Accepted v${aupVersion}${
              aupAgreedAt ? ` on ${new Date(aupAgreedAt).toLocaleString()}` : ''
            }`}
          />
        ) : (
          <Chip size='small' label='Not accepted' />
        )}
      </Box>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Clearing this user's acceptance forces them through the AUP workflow on
        their next page load. Use this when you need to re-prompt a single user
        without rotating the policy version (which would re-prompt everyone).
      </Typography>
      <InlineConfirmButton
        variant='outlined'
        color='warning'
        onConfirm={onClick}
        disabled={busy || !accepted}
        confirmLabel='Yes, clear acceptance'
      >
        Clear AUP acceptance
      </InlineConfirmButton>
    </Box>
  );
};

// PasswordSection surfaces the current credential state ("local password
// is set / not set") plus the two admin actions: mint a password-set
// invite (so the user can pick their own — admins never see it) and
// clear an existing password (lock the account out of password login
// without learning what it was). Setting the password directly is
// intentionally NOT exposed.
const PasswordSection: React.FC<{ userId: string; hasPassword?: boolean }> = ({
  userId,
  hasPassword,
}) => (
  <Box>
    <Typography variant='h6' sx={{ mb: 1 }}>
      Local password
    </Typography>
    <Box display='flex' alignItems='center' gap={1} sx={{ mb: 2 }}>
      <Typography variant='body2'>Status:</Typography>
      {hasPassword ? (
        <Chip size='small' color='success' label='Password set' />
      ) : (
        <Chip size='small' label='No password set' />
      )}
    </Box>
    <PasswordInviteSection userId={userId} />
    {hasPassword && (
      <Box sx={{ mt: 2 }}>
        <ClearPasswordButton userId={userId} />
      </Box>
    )}
  </Box>
);

const ClearPasswordButton: React.FC<{ userId: string }> = ({ userId }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState(false);
  const doClear = async () => {
    setBusy(true);
    let success = false;
    try {
      await alertOnError(
        () => UserService.clearPassword(userId),
        'Failed to clear password',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error */
    }
    setBusy(false);
    if (!success) return;
    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: 'Local password cleared',
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    // Reflect the new state without a full reload.
    // (useServiceSWR cache key is internal to useServiceSWR; for
    // simplicity we just reload the page to pick up the fresh
    // hasPassword from the User record.)
    window.location.reload();
  };
  return (
    <InlineConfirmButton
      variant='outlined'
      color='warning'
      onConfirm={doClear}
      disabled={busy}
      confirmLabel='Yes, clear password'
    >
      Clear local password
    </InlineConfirmButton>
  );
};

// ScopesSection lists the *direct* user_scopes grants on this user
// (NOT the full effective set, which would also include scopes
// inherited from group membership and config). The chip + revoke UX
// matches "things this user has been granted directly"; group/config
// inheritance is shown contextually elsewhere (groups page,
// Server.UIAdminUsers config) so we don't double-render here.
//
// The picker only offers user-grantable scopes that aren't already
// directly granted — it doesn't filter out group/config-inherited
// ones, so an admin who wants to "pin" a config-derived grant onto
// the user record can still do so.
const ScopesSection: React.FC<{ userId: string }> = ({ userId }) => {
  const dispatch = useContext(AlertDispatchContext);
  const { data: grants, mutate } = useSWR<UserScopeGrant[] | undefined>(
    `users/${userId}/scopes`,
    () =>
      alertOnError(
        () => ScopeService.listUser(userId),
        'Failed to load user scopes',
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
  // Keep the FULL catalog entries (not just names) so we can render
  // the description alongside the name on the picker. Filter to drop
  // already-granted scopes — that's a UX courtesy; the backend
  // re-checks anyway.
  const candidates: ScopeCatalogEntry[] = (catalog || []).filter(
    (c) => !grantedNames.has(c.name)
  );

  // Look up the description for a granted scope so the chip's
  // tooltip still surfaces "what this means" even after the picker
  // is gone. Catalog might not have loaded yet — fall back to "" so
  // the tooltip just hides.
  const describeScope = (name: string): string =>
    (catalog || []).find((c) => c.name === name)?.description ?? '';

  const grant = async () => {
    if (!picker) return;
    const scopeName = picker.name;
    setBusy(`grant:${scopeName}`);
    let success = false;
    try {
      await alertOnError(
        () => ScopeService.grantUser(userId, scopeName),
        'Failed to grant scope',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error */
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
        () => ScopeService.revokeUser(userId, scope),
        'Failed to revoke scope',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error */
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
      <Typography variant='h6' sx={{ mb: 1 }}>
        Scopes
      </Typography>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Direct grants on this user. The user may inherit additional scopes via
        group membership or the legacy config (Server.UIAdminUsers, etc.); those
        are evaluated live and don't appear here.
      </Typography>
      {!grants || grants.length === 0 ? (
        <Typography variant='body2' color='text.secondary' fontStyle='italic'>
          No direct scope grants.
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
      {/* Show the description of the currently-selected option BELOW
          the picker too — having it inline (not just inside the
          dropdown) makes the consequences obvious before the admin
          clicks Grant. */}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <Autocomplete
          sx={{ flexGrow: 1, minWidth: 280 }}
          size='small'
          options={candidates}
          value={picker}
          onChange={(_, v) => setPicker(v)}
          getOptionLabel={(o) => o.name}
          isOptionEqualToValue={(a, b) => a.name === b.name}
          noOptionsText='Every catalog scope is already granted directly.'
          renderOption={(props, option) => {
            // Strip key out of the spread; React requires it as a
            // direct prop on the JSX element, not via {...props}.
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

// IdentitiesSection lists the user's *secondary* OIDC identities (rows
// in user_identities) and lets the admin unlink any of them. The
// user's *primary* identity is on the User row itself and isn't
// removable here — admins manage that via /users/{id} PATCH (which
// only allows username, not sub/issuer; primary identity rotation is
// out of scope for the admin UI).
const IdentitiesSection: React.FC<{ userId: string }> = ({ userId }) => {
  const dispatch = useContext(AlertDispatchContext);
  const { data: identities, mutate } = useSWR<UserIdentity[] | undefined>(
    `users/${userId}/identities`,
    () =>
      alertOnError(
        () => UserService.listIdentities(userId),
        'Failed to load identities',
        dispatch
      ),
    { fallbackData: [] }
  );
  const [busy, setBusy] = useState<string | null>(null);

  const unlink = async (identity: UserIdentity) => {
    setBusy(identity.id);
    let success = false;
    try {
      await alertOnError(
        () => UserService.unlinkIdentity(userId, identity.id),
        'Failed to unlink identity',
        dispatch,
        true
      );
      success = true;
    } catch {
      /* alertOnError already dispatched the error */
    }
    setBusy(null);
    if (!success) return;
    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: 'Identity unlinked',
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    mutate();
  };

  return (
    <Box>
      <Typography variant='h6' sx={{ mb: 1 }}>
        Linked identities
      </Typography>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Secondary OIDC identities the user has linked. The primary identity
        (shown above on the form) is not unlinkable from here.
      </Typography>
      {!identities || identities.length === 0 ? (
        <Typography variant='body2' color='text.secondary' fontStyle='italic'>
          No secondary identities linked.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {identities.map((id) => (
            <Box
              key={id.id}
              display='flex'
              alignItems='center'
              justifyContent='space-between'
              sx={{
                p: 1.5,
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 1,
                gap: 1,
              }}
            >
              <Box minWidth={0} sx={{ wordBreak: 'break-all' }}>
                <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
                  {id.sub}
                </Typography>
                <Typography
                  variant='caption'
                  color='text.secondary'
                  sx={{ fontFamily: 'monospace' }}
                >
                  at {id.issuer}
                </Typography>
              </Box>
              {/* Inline confirm via the icon-style ConfirmButton —
                  click expands into a "Confirm? × ✓" pair next to
                  the icon, no window.confirm modal. */}
              <ConfirmButton
                color='warning'
                onConfirm={() => unlink(id)}
                disabled={busy === id.id}
                aria-label={`Unlink identity ${id.sub}`}
                title={`Unlink ${id.sub}`}
              >
                <LinkOffIcon fontSize='small' />
              </ConfirmButton>
            </Box>
          ))}
        </Stack>
      )}
    </Box>
  );
};

// PasswordInviteSection lets the admin mint a single-use, time-bounded
// password-set invite for the user — and shows them the link to hand
// over. There is intentionally no field where the admin types a password;
// the user picks their own when they redeem the link, so the admin never
// learns it.
const PasswordInviteSection: React.FC<{ userId: string }> = ({ userId }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState(false);
  // The freshly-minted link for this admin session. Clears on page nav,
  // and we never call the listing endpoint to surface this token again
  // because the backend doesn't store the plaintext (by design).
  const [created, setCreated] = useState<InviteLinkCreated | null>(null);

  const { data: existing, mutate } = useSWR<InviteLinkBase[] | undefined>(
    `password-invites/${userId}`,
    () =>
      alertOnError(
        () => InviteService.listPasswordInvites(userId),
        'Failed to load password invites',
        dispatch
      ),
    { fallbackData: [] }
  );

  const generate = async () => {
    setBusy(true);
    const link = await alertOnError(
      () => InviteService.createPasswordInvite(userId),
      'Failed to create password invite',
      dispatch
    );
    if (link) {
      setCreated(link);
      mutate();
    }
    setBusy(false);
  };

  // Build the URL the admin should hand to the user. We use the current
  // origin (i.e. the URL the admin is hitting) so that whatever Pelican
  // hostname the admin uses, the recipient gets a working link.
  const linkUrl = (token: string) =>
    `${window.location.origin}/view/invite/redeem?token=${encodeURIComponent(token)}`;

  // Outstanding (live) invites — surface so the admin doesn't pile up
  // unused links.
  const live = (existing || []).filter(
    (l) => !l.revoked && !l.redeemedBy && new Date(l.expiresAt) > new Date()
  );

  return (
    <Box>
      <Typography variant='h6' sx={{ mb: 1 }}>
        Password setup
      </Typography>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Generate a single-use invite link the user follows to set their own
        password. Admins do not see or set passwords directly.
      </Typography>

      {created && (
        <Alert severity='success' sx={{ mb: 2 }}>
          <Typography variant='body2' sx={{ mb: 1 }}>
            Hand this URL to the user. It is shown <strong>only once</strong>.
            It expires {new Date(created.expiresAt).toLocaleString()} and can
            only be used once.
          </Typography>
          <Stack direction='row' spacing={1} alignItems='center'>
            <TextField
              size='small'
              fullWidth
              value={linkUrl(created.inviteToken)}
              slotProps={{
                input: {
                  readOnly: true,
                  style: { fontFamily: 'monospace', fontSize: '0.8rem' },
                },
              }}
            />
            <Tooltip title='Copy URL'>
              <IconButton
                onClick={() =>
                  navigator.clipboard.writeText(linkUrl(created.inviteToken))
                }
              >
                <ContentCopyIcon fontSize='small' />
              </IconButton>
            </Tooltip>
          </Stack>
        </Alert>
      )}

      <Stack direction='row' spacing={1} alignItems='center' sx={{ mb: 2 }}>
        <Button variant='contained' onClick={generate} disabled={busy}>
          Generate password-set invite
        </Button>
        {live.length > 0 && !created && (
          <Chip
            size='small'
            color='warning'
            label={`${live.length} outstanding invite${live.length === 1 ? '' : 's'}`}
          />
        )}
      </Stack>

      {(existing || []).length > 0 && (
        <PasswordInviteHistory invites={existing!} />
      )}
    </Box>
  );
};

// PasswordInviteHistory shows the audit trail for password invites
// targeting this user. The plaintext token is intentionally never
// surfaced here — it only appears once at creation time.
const PasswordInviteHistory: React.FC<{ invites: InviteLinkBase[] }> = ({
  invites,
}) => (
  <Box>
    <Typography variant='subtitle2' sx={{ mb: 1 }}>
      Invite history
    </Typography>
    <Stack spacing={1}>
      {invites.map((l) => {
        const status = l.revoked
          ? 'Revoked'
          : l.redeemedBy
            ? `Used ${l.redeemedAt ? new Date(l.redeemedAt).toLocaleString() : ''}`
            : new Date(l.expiresAt) < new Date()
              ? 'Expired'
              : 'Outstanding';
        return (
          <Box
            key={l.id}
            display='flex'
            justifyContent='space-between'
            alignItems='center'
            sx={{
              p: 1,
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 1,
            }}
          >
            <Box>
              <Box display='flex' alignItems='center' gap={1}>
                {/*
                  tokenPrefix is the public short ID — first few chars
                  of the plaintext token. Lets the admin tell multiple
                  outstanding setup links apart without ever pasting
                  the full token (which IS the credential).
                */}
                {l.tokenPrefix && (
                  <Chip
                    size='small'
                    variant='outlined'
                    sx={{ fontFamily: 'monospace' }}
                    label={l.tokenPrefix}
                  />
                )}
                <Typography variant='body2'>{status}</Typography>
              </Box>
              <Typography variant='caption' color='text.secondary'>
                Created {new Date(l.createdAt).toLocaleString()} · expires{' '}
                {new Date(l.expiresAt).toLocaleString()} · via{' '}
                {l.authMethod || 'unknown'}
                {l.authMethodId ? ` (${l.authMethodId})` : ''}
              </Typography>
            </Box>
          </Box>
        );
      })}
    </Stack>
  </Box>
);

export default Page;
