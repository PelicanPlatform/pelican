'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import UserForm from '../components/UserForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import SettingHeader from '@/app/settings/components/SettingHeader';
import {
  Alert,
  Box,
  Breadcrumbs,
  Button,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  InviteService,
  InviteLinkCreated,
  User,
  UserPost,
  UserService,
} from '@/helpers/api';

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);
  const router = useRouter();

  const [isSubmitting, setIsSubmitting] = useState(false);
  // For local users we let the admin generate a password-set invite right
  // away — surfacing the link here is what unlocks the new account.
  // For OIDC users the link isn't relevant, so we just go back to the list.
  const [created, setCreated] = useState<User | null>(null);
  const [invite, setInvite] = useState<InviteLinkCreated | null>(null);
  const [issuingInvite, setIssuingInvite] = useState(false);

  // A user is "local" when sub/issuer aren't set on submit (matches the
  // backend's heuristic). We use that to decide whether to offer the
  // password-invite step.
  const wasLocal = (u: UserPost) => !u.sub && !u.issuer;

  const onCreate = async (form: UserPost) => {
    setIsSubmitting(true);
    const response = await alertOnError(
      async () => UserService.post(form),
      'Error Creating New User',
      dispatch
    );
    if (response) {
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: 'Created user',
          autoHideDuration: 3000,
          alertProps: { severity: 'success' },
        },
      });
      if (wasLocal(form)) {
        // Stay on the page so the admin can mint the password invite.
        setCreated(response);
      } else {
        router.push('../');
      }
    }
    setIsSubmitting(false);
  };

  const issueInvite = async () => {
    if (!created) return;
    setIssuingInvite(true);
    const link = await alertOnError(
      () => InviteService.createPasswordInvite(created.id),
      'Failed to create password invite',
      dispatch
    );
    if (link) {
      setInvite(link);
    }
    setIssuingInvite(false);
  };

  const linkUrl = (token: string) =>
    `${window.location.origin}/view/invite/redeem?token=${encodeURIComponent(token)}`;

  return (
    <>
      <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
        <Link href={'../'}>Users</Link>
        <Typography sx={{ color: 'text.primary' }}>Add</Typography>
      </Breadcrumbs>
      <SettingHeader title={'Add User'} />

      {!created && (
        <UserForm onSubmit={onCreate} isSubmitting={isSubmitting} />
      )}

      {created && !invite && (
        <Box>
          <Alert severity='success' sx={{ mb: 2 }}>
            Created <strong>{created.username}</strong>. Generate a password-set
            invite below and hand the link to the user; they will pick their
            own password (admins do not see it).
          </Alert>
          <Stack direction='row' spacing={1}>
            <Button
              variant='contained'
              onClick={issueInvite}
              disabled={issuingInvite}
            >
              {issuingInvite ? 'Generating…' : 'Generate password-set invite'}
            </Button>
            <Button onClick={() => router.push('../')}>Skip for now</Button>
          </Stack>
        </Box>
      )}

      {invite && (
        <Box>
          <Alert severity='success' sx={{ mb: 2 }}>
            Hand this URL to the user. It is shown <strong>only once</strong>,
            expires {new Date(invite.expiresAt).toLocaleString()}, and can
            only be used once.
          </Alert>
          <Stack direction='row' spacing={1} alignItems='center' sx={{ mb: 2 }}>
            <TextField
              size='small'
              fullWidth
              value={linkUrl(invite.inviteToken)}
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
                  navigator.clipboard.writeText(linkUrl(invite.inviteToken))
                }
              >
                <ContentCopyIcon fontSize='small' />
              </IconButton>
            </Tooltip>
          </Stack>
          <Button onClick={() => router.push('../')}>Done</Button>
        </Box>
      )}
    </>
  );
};

export default Page;
