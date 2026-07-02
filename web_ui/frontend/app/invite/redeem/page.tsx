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

import React, { Suspense, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Container,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useRouter, useSearchParams } from 'next/navigation';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { getErrorMessage } from '@/helpers/util';
import { InviteInfo, InviteService } from '@/helpers/api';
import CollectionService from '@/helpers/api/Collection/service';

// The redemption page handles two invite kinds:
//
//   - password : NO authentication required. The token is the credential.
//                The user picks a new password and the link redeems them
//                directly into having one. (Admin never sees the password.)
//   - group    : Caller must be authenticated; the token only adds the
//                caller's existing user account to a group.
//
// We probe `/invites/info?token=` BEFORE deciding whether to require
// authentication, so a brand-new user who has never logged in can still
// follow a password-set link without an auth wall in their face.

const Page = () => {
  return (
    // No AuthenticatedContent wrapper at this level — for password
    // invites (the new-user case) we explicitly do not want to force a
    // login first. Group-invite redemption nests AuthenticatedContent
    // internally only after we know the kind.
    //
    // The Suspense boundary is required: with `output: 'export'`,
    // Next 15 refuses to statically prerender any component that
    // calls useSearchParams() unless its read is suspended at a
    // parent boundary (otherwise the prerender can't decide what URL
    // it's on). The fallback never actually renders in practice
    // because useSearchParams() resolves synchronously on the client;
    // it exists only to satisfy the build.
    <Container maxWidth='sm' sx={{ py: 6 }}>
      <Suspense fallback={<RedeemSkeleton />}>
        <RedeemRouter />
      </Suspense>
    </Container>
  );
};

const RedeemSkeleton: React.FC = () => (
  <Paper variant='outlined' sx={{ p: 4 }}>
    <Stack spacing={2} alignItems='center'>
      <CircularProgress size={24} />
      <Typography variant='body2' color='text.secondary'>
        Loading invite…
      </Typography>
    </Stack>
  </Paper>
);

const RedeemRouter: React.FC = () => {
  const params = useSearchParams();
  const router = useRouter();
  const initialToken = (params.get('token') || '').trim();

  const [token, setToken] = useState(initialToken);
  const [info, setInfo] = useState<InviteInfo | null>(null);
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  // Auto-probe when the page loads with a token already in the URL.
  useEffect(() => {
    if (initialToken && !info && !probing) {
      void probe(initialToken);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialToken]);

  const probe = async (t: string) => {
    setProbing(true);
    setProbeError(null);
    try {
      const i = await InviteService.info(t);
      setInfo(i);
    } catch (err) {
      let message = 'Invite not found, expired, or already used.';
      if (err instanceof Response) {
        try {
          message = await getErrorMessage(err);
        } catch {
          /* fall through to default message */
        }
      } else if (err instanceof Error) {
        message = err.message;
      }
      setProbeError(message);
    } finally {
      setProbing(false);
    }
  };

  // Manual entry / re-probe form. Shown until we have a probed `info`.
  if (!info) {
    return (
      <Paper variant='outlined' sx={{ p: 4 }}>
        <Stack spacing={3}>
          <Box>
            <Typography variant='h4' gutterBottom>
              Redeem invite
            </Typography>
            <Typography variant='body2' color='text.secondary'>
              Paste your invite token below. If you arrived from an invite URL
              the token is already filled in.
            </Typography>
          </Box>
          {probeError && <Alert severity='error'>{probeError}</Alert>}
          <TextField
            label='Invite token'
            value={token}
            onChange={(e) => setToken(e.target.value)}
            disabled={probing}
            autoFocus={!initialToken}
            fullWidth
            slotProps={{
              input: { style: { fontFamily: 'monospace' } },
            }}
          />
          <Box display='flex' justifyContent='flex-end' gap={1}>
            <Button onClick={() => router.push('/')} disabled={probing}>
              Cancel
            </Button>
            <Button
              variant='contained'
              onClick={() => probe(token.trim())}
              disabled={probing || !token.trim()}
            >
              {probing ? <CircularProgress size={20} /> : 'Continue'}
            </Button>
          </Box>
        </Stack>
      </Paper>
    );
  }

  if (info.kind === 'password') {
    return <PasswordRedeem token={token} />;
  }
  if (info.kind === 'collection_ownership') {
    return <CollectionOwnershipRedeem token={token} info={info} />;
  }
  return <GroupRedeem token={token} info={info} />;
};

// ============================================================================
// Password kind: pick a new password. NO authentication on the page —
// possession of the token IS the credential.
// ============================================================================

const PasswordRedeem: React.FC<{ token: string }> = ({ token }) => {
  const router = useRouter();
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mismatch = pw !== '' && confirm !== '' && pw !== confirm;
  const tooShort = pw !== '' && pw.length < 8;
  const canSubmit = pw.length >= 8 && pw === confirm && !submitting;

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await InviteService.redeemPassword(token, pw);
      setDone(true);
    } catch (err) {
      let message = 'Failed to set password';
      if (err instanceof Response) {
        try {
          message = await getErrorMessage(err);
        } catch {
          /* default */
        }
      } else if (err instanceof Error) {
        message = err.message;
      }
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  if (done) {
    return (
      <Paper variant='outlined' sx={{ p: 4 }}>
        <Stack spacing={2}>
          <Typography variant='h4'>Password set</Typography>
          <Alert severity='success'>
            You can now log in with your username and the password you just
            chose.
          </Alert>
          <Box display='flex' gap={1}>
            <Button variant='contained' onClick={() => router.push('/login/')}>
              Go to login
            </Button>
          </Box>
        </Stack>
      </Paper>
    );
  }

  return (
    <Paper variant='outlined' sx={{ p: 4 }}>
      <Stack spacing={2}>
        <Typography variant='h4'>Set your password</Typography>
        <Typography variant='body2' color='text.secondary'>
          Pick a password of at least 8 characters. The administrator who sent
          you this link does not see it.
        </Typography>
        {error && <Alert severity='error'>{error}</Alert>}
        <TextField
          label='New password'
          type='password'
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          disabled={submitting}
          autoComplete='new-password'
          error={tooShort}
          helperText={tooShort ? 'At least 8 characters' : ''}
          fullWidth
          autoFocus
        />
        <TextField
          label='Confirm password'
          type='password'
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={submitting}
          autoComplete='new-password'
          error={mismatch}
          helperText={mismatch ? 'Passwords do not match' : ''}
          fullWidth
        />
        <Box display='flex' justifyContent='flex-end' gap={1}>
          <Button onClick={() => router.push('/')} disabled={submitting}>
            Cancel
          </Button>
          <Button variant='contained' onClick={submit} disabled={!canSubmit}>
            {submitting ? 'Setting…' : 'Set password'}
          </Button>
        </Box>
      </Stack>
    </Paper>
  );
};

// ============================================================================
// Group kind: requires the redeemer to be authenticated. AuthenticatedContent
// wrapping forces a /login round-trip if not yet signed in.
// ============================================================================

const GroupRedeem: React.FC<{ token: string; info: InviteInfo }> = ({
  token,
  info,
}) => {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Show the most informative label we have: prefer the human display
  // name, fall back to the machine name, and finally to the opaque ID.
  // The confirm-join page MUST tell the user which group they're about
  // to be added to — without that they can't tell legitimate invites
  // apart from misdirected ones.
  const groupLabel =
    info.groupDisplayName?.trim() ||
    info.groupName ||
    info.groupId ||
    'an unnamed group';
  // Only render the "(name)" parenthetical when the display name is
  // present and differs from the machine name; otherwise it's noise.
  const showMachineName =
    !!info.groupDisplayName?.trim() &&
    !!info.groupName &&
    info.groupDisplayName.trim() !== info.groupName;

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await InviteService.redeem(token);
      setDone(true);
    } catch (err) {
      let message = 'Failed to redeem invite';
      if (err instanceof Response) {
        try {
          message = await getErrorMessage(err);
        } catch {
          /* default */
        }
      } else if (err instanceof Error) {
        message = err.message;
      }
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  if (done) {
    return (
      <Paper variant='outlined' sx={{ p: 4 }}>
        <Stack spacing={2}>
          <Typography variant='h4'>You're in</Typography>
          <Alert severity='success'>
            The invite was redeemed. The new group should appear on your
            profile.
          </Alert>
          <Box display='flex' gap={1}>
            <Button
              variant='contained'
              onClick={() => router.push('/profile/')}
            >
              Go to profile
            </Button>
            <Button variant='text' onClick={() => router.push('/')}>
              Home
            </Button>
          </Box>
        </Stack>
      </Paper>
    );
  }

  return (
    <AuthenticatedContent redirect>
      <Paper variant='outlined' sx={{ p: 4 }}>
        <Stack spacing={2}>
          <Typography variant='h4'>Join group</Typography>
          <Typography variant='body1'>
            You'll be added to{' '}
            <Box component='span' sx={{ fontWeight: 600 }}>
              {groupLabel}
            </Box>
            {showMachineName && (
              <Typography
                component='span'
                variant='body2'
                color='text.secondary'
                sx={{ ml: 1, fontFamily: 'monospace' }}
              >
                ({info.groupName})
              </Typography>
            )}
            .
          </Typography>
          <Typography variant='body2' color='text.secondary'>
            Accepting will add your account as a member of this group.
          </Typography>
          {error && <Alert severity='error'>{error}</Alert>}
          <Box display='flex' justifyContent='flex-end' gap={1}>
            <Button onClick={() => router.push('/')} disabled={submitting}>
              Cancel
            </Button>
            <Button variant='contained' onClick={submit} disabled={submitting}>
              {submitting ? 'Joining…' : 'Accept invite'}
            </Button>
          </Box>
        </Stack>
      </Paper>
    </AuthenticatedContent>
  );
};

// ============================================================================
// Collection-ownership kind: redeemer must be authenticated. On accept,
// Collection.OwnerID transfers from the previous owner to the
// authenticated caller. Single-use is enforced server-side, so a
// successful redemption invalidates the link.
// ============================================================================

const CollectionOwnershipRedeem: React.FC<{
  token: string;
  info: InviteInfo;
}> = ({ token, info }) => {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const collectionLabel =
    info.collectionName?.trim() || info.collectionId || 'an unnamed collection';

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await CollectionService.redeemOwnershipInvite(token);
      setDone(true);
    } catch (err) {
      let message = 'Failed to redeem invite';
      if (err instanceof Response) {
        try {
          message = await getErrorMessage(err);
        } catch {
          /* default */
        }
      } else if (err instanceof Error) {
        message = err.message;
      }
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  if (done) {
    return (
      <Paper variant='outlined' sx={{ p: 4 }}>
        <Stack spacing={2}>
          <Typography variant='h4'>Ownership transferred</Typography>
          <Alert severity='success'>
            You are now the owner of <strong>{collectionLabel}</strong>
            {info.collectionNamespace && (
              <>
                {' '}
                (<code>{info.collectionNamespace}</code>)
              </>
            )}
            .
          </Alert>
          <Box display='flex' gap={1}>
            <Button
              variant='contained'
              onClick={() => {
                if (info.collectionId) {
                  router.push(
                    `/origin/collections/edit/?id=${encodeURIComponent(info.collectionId)}`
                  );
                } else {
                  router.push('/origin/collections/');
                }
              }}
            >
              Manage collection
            </Button>
            <Button variant='text' onClick={() => router.push('/')}>
              Home
            </Button>
          </Box>
        </Stack>
      </Paper>
    );
  }

  return (
    <AuthenticatedContent redirect>
      <Paper variant='outlined' sx={{ p: 4 }}>
        <Stack spacing={2}>
          <Typography variant='h4'>Accept collection ownership</Typography>
          <Typography variant='body1'>
            Accepting will make you the owner of{' '}
            <Box component='span' sx={{ fontWeight: 600 }}>
              {collectionLabel}
            </Box>
            {info.collectionNamespace && (
              <>
                {' '}
                rooted at{' '}
                <Box
                  component='span'
                  sx={{ fontFamily: 'monospace', fontWeight: 600 }}
                >
                  {info.collectionNamespace}
                </Box>
              </>
            )}
            .
          </Typography>
          {error && <Alert severity='error'>{error}</Alert>}
          <Box display='flex' justifyContent='flex-end' gap={1}>
            <Button onClick={() => router.push('/')} disabled={submitting}>
              Cancel
            </Button>
            <Button variant='contained' onClick={submit} disabled={submitting}>
              {submitting ? 'Accepting…' : 'Accept ownership'}
            </Button>
          </Box>
        </Stack>
      </Paper>
    </AuthenticatedContent>
  );
};

export default Page;
