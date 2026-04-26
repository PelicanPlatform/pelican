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
  Box,
  Button,
  Chip,
  FormControlLabel,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import { ContentCopy, Delete, Refresh } from '@mui/icons-material';
import { GroupInviteLink } from '@/types';
import { fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import UserPill from './UserPill';

interface InviteLinksPanelProps {
  groupId: string;
}

const DEFAULT_EXPIRY = '168h'; // 7d, matches Server.GroupInviteLinkExpiration default

// inviteUrl builds the full URL the admin should hand to the user, using
// the current origin so links generated against any Pelican hostname
// resolve back to the same instance the recipient is meant to land on.
const inviteUrl = (token: string): string =>
  typeof window === 'undefined'
    ? `/view/invite/redeem?token=${encodeURIComponent(token)}`
    : `${window.location.origin}/view/invite/redeem?token=${encodeURIComponent(token)}`;

const InviteLinksPanel: React.FC<InviteLinksPanelProps> = ({ groupId }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [links, setLinks] = useState<GroupInviteLink[]>([]);
  const [loading, setLoading] = useState(false);
  const [singleUse, setSingleUse] = useState(false);
  const [expiresIn, setExpiresIn] = useState(DEFAULT_EXPIRY);
  const [generatedToken, setGeneratedToken] = useState('');
  const [creating, setCreating] = useState(false);

  const refresh = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/v1.0/groups/${groupId}/invites`);
      if (r.ok) {
        setLinks(await r.json());
      } else {
        setLinks([]);
      }
    } catch {
      setLinks([]);
    } finally {
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const generate = async () => {
    setCreating(true);
    const ok = await alertOnError(
      async () =>
        fetchApi(async () =>
          fetch(`/api/v1.0/groups/${groupId}/invites`, {
            method: 'POST',
            body: JSON.stringify({
              isSingleUse: singleUse,
              expiresIn: expiresIn || DEFAULT_EXPIRY,
            }),
          })
        ),
      'Failed to generate invite link',
      dispatch
    );
    setCreating(false);
    if (ok) {
      const data = await ok.json();
      setGeneratedToken(data.inviteToken || '');
      refresh();
    }
  };

  const revoke = async (linkId: string) => {
    const ok = await alertOnError(
      async () =>
        fetchApi(async () =>
          fetch(`/api/v1.0/groups/${groupId}/invites/${linkId}`, {
            method: 'DELETE',
          })
        ),
      'Failed to revoke invite link',
      dispatch
    );
    if (ok) refresh();
  };

  return (
    <Box>
      <Box display='flex' alignItems='center' justifyContent='space-between' mb={1}>
        <Typography variant='subtitle1'>Invite links</Typography>
        <IconButton size='small' onClick={refresh} title='Refresh'>
          <Refresh fontSize='small' />
        </IconButton>
      </Box>

      {generatedToken && (
        <Box
          mb={2}
          p={1.5}
          sx={{ bgcolor: 'success.light', borderRadius: 1 }}
        >
          <Typography variant='body2' fontWeight={600} mb={1}>
            New invite link (copy now — won&apos;t be shown again):
          </Typography>
          <Typography variant='caption' color='text.secondary' mb={1} display='block'>
            Send this URL to whoever should join the group. The page on
            the other end requires them to be logged in (any identity)
            and adds them on accept.
          </Typography>
          {/*
            We send the *full URL* — not the bare token. The token alone
            isn't actionable for a recipient who doesn't already know
            where to paste it; the URL form is what email/IM/etc.
            handlers will reliably render as a click target.
          */}
          <Box display='flex' alignItems='center' gap={1}>
            <TextField
              value={inviteUrl(generatedToken)}
              fullWidth
              size='small'
              slotProps={{
                input: {
                  readOnly: true,
                  style: { fontFamily: 'monospace', fontSize: '0.8rem' },
                },
              }}
            />
            <IconButton
              onClick={() =>
                navigator.clipboard.writeText(inviteUrl(generatedToken))
              }
              title='Copy URL'
            >
              <ContentCopy />
            </IconButton>
          </Box>
        </Box>
      )}

      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        spacing={1}
        alignItems={{ sm: 'center' }}
        mb={2}
      >
        <FormControlLabel
          control={
            <Switch
              size='small'
              checked={singleUse}
              onChange={(e) => setSingleUse(e.target.checked)}
            />
          }
          label='Single use'
        />
        <TextField
          size='small'
          label='Expires in'
          value={expiresIn}
          onChange={(e) => setExpiresIn(e.target.value)}
          helperText='Go duration, e.g. 168h, 24h, 30m'
          sx={{ minWidth: 180 }}
        />
        <Button
          variant='contained'
          onClick={generate}
          disabled={creating || !expiresIn}
        >
          Generate invite link
        </Button>
      </Stack>

      {loading ? (
        <Typography color='text.secondary'>Loading…</Typography>
      ) : links.length === 0 ? (
        <Typography color='text.secondary'>No invite links yet.</Typography>
      ) : (
        <List dense>
          {links.map((l) => (
            <ListItem
              key={l.id}
              secondaryAction={
                !l.revoked && (
                  <IconButton
                    edge='end'
                    title='Revoke'
                    onClick={() => revoke(l.id)}
                    color='error'
                  >
                    <Delete />
                  </IconButton>
                )
              }
              sx={{
                bgcolor: l.revoked ? 'action.disabledBackground' : undefined,
              }}
            >
              <ListItemText
                primary={
                  <Box display='flex' alignItems='center' gap={1} flexWrap='wrap'>
                    {/*
                      tokenPrefix is the public short ID — first few chars
                      of the plaintext token. Showing it here lets admins
                      tell multiple outstanding invites apart without ever
                      pasting the full token (which is the credential).
                    */}
                    {l.tokenPrefix && (
                      <Chip
                        size='small'
                        variant='outlined'
                        sx={{ fontFamily: 'monospace' }}
                        label={l.tokenPrefix}
                      />
                    )}
                    <Chip
                      size='small'
                      label={l.isSingleUse ? 'single-use' : 'multi-use'}
                    />
                    <Typography variant='body2'>
                      Expires {new Date(l.expiresAt).toLocaleString()}
                    </Typography>
                  </Box>
                }
                secondary={
                  l.revoked ? (
                    'Revoked'
                  ) : l.redeemedBy ? (
                    // Render redeemed-by as a user pill ("Display Name
                    // (username)") rather than the raw opaque ID, which
                    // is unreadable. The backend already resolves the
                    // card in InviteLinkView; we fall back to the bare
                    // ID only if that lookup didn't find anyone.
                    <Box
                      component='span'
                      display='inline-flex'
                      alignItems='center'
                      gap={0.5}
                    >
                      <span>Redeemed by</span>
                      <UserPill
                        card={l.redeemedByUser}
                        id={l.redeemedBy}
                      />
                    </Box>
                  ) : (
                    'Active'
                  )
                }
              />
            </ListItem>
          ))}
        </List>
      )}
    </Box>
  );
};

export default InviteLinksPanel;
