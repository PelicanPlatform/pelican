'use client';

import React, { useState } from 'react';
import {
  TextField,
  Button,
  Box,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  FormHelperText,
} from '@mui/material';
import { UserPatch, UserPost, User } from '@/helpers/api';

type CreateUserFormProps = {
  user?: undefined;
  onSubmit: (newUser: UserPost) => Promise<void>;
  isSubmitting?: boolean;
};

type UpdateUserFormProps = {
  user: User;
  onSubmit: (updatedUser: UserPatch) => Promise<void>;
  isSubmitting?: boolean;
};

type UserFormProps = CreateUserFormProps | UpdateUserFormProps;

type UserKind = 'local' | 'oidc';

const UserForm: React.FC<UserFormProps> = ({
  user,
  onSubmit,
  isSubmitting = false,
}) => {
  const [username, setUsername] = useState(user?.username || '');
  const [displayName, setDisplayName] = useState(user?.displayName || '');
  const [sub, setSub] = useState('');
  const [issuer, setIssuer] = useState('');
  // No password field — admins do NOT set passwords. After creating a
  // local user, mint a password-set invite (see the edit page) and hand
  // the link to the user; they pick their own password.
  //
  // The kind toggle only appears when creating (it is hidden in edit mode
  // below), and sub/issuer are only submitted on create, so the initial value
  // matters just for the create form, which starts as a local account. A
  // user's identities are no longer carried on the User record — they are
  // managed through the identities endpoints — so there is nothing to detect
  // here for an existing record.
  const [kind, setKind] = useState<UserKind>('local');

  const isEdit = Boolean(user);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (user) {
      // Edit: only mutable fields go through PATCH. Identity-linkage and
      // password are changed via dedicated flows.
      await onSubmit({
        id: user.id,
        username,
        displayName,
      } as UserPatch);
    } else if (kind === 'local') {
      await onSubmit({
        username,
        displayName: displayName || undefined,
      });
    } else {
      await onSubmit({
        username,
        displayName: displayName || undefined,
        sub,
        issuer,
      });
    }
  };

  return (
    <Box component='form' onSubmit={handleSubmit}>
      <Stack spacing={2}>
        {!isEdit && (
          <Box>
            <ToggleButtonGroup
              value={kind}
              exclusive
              size='small'
              onChange={(_, v) => v && setKind(v)}
            >
              <ToggleButton value='local'>
                Local (username + password)
              </ToggleButton>
              <ToggleButton value='oidc'>External (OIDC)</ToggleButton>
            </ToggleButtonGroup>
            <FormHelperText sx={{ mt: 0.5 }}>
              {kind === 'local'
                ? 'User logs in with this server using a username and password. After creating the user, generate a password-set invite from their profile page; the user picks their own password.'
                : 'User logs in via your configured OIDC provider; supply their sub and issuer.'}
            </FormHelperText>
          </Box>
        )}
        <TextField
          id='username'
          label='Username'
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={isSubmitting}
          size='small'
          helperText='String identifier for the user.'
          required
          fullWidth
        />
        <TextField
          id='displayName'
          label='Display name'
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          disabled={isSubmitting}
          size='small'
          helperText='Optional human-readable name.'
          fullWidth
        />
        {kind === 'oidc' && (
          <>
            <TextField
              id='sub'
              label='Sub'
              value={sub}
              onChange={(e) => setSub(e.target.value)}
              disabled={isSubmitting}
              size='small'
              helperText='Subject Identifier from the OIDC provider.'
              required
              fullWidth
            />
            <TextField
              id='issuer'
              label='Issuer'
              value={issuer}
              onChange={(e) => setIssuer(e.target.value)}
              disabled={isSubmitting}
              size='small'
              helperText='Issuer URL from the OIDC provider.'
              required
              fullWidth
            />
          </>
        )}
        <Button
          type='submit'
          variant='contained'
          color='primary'
          disabled={isSubmitting}
        >
          {user ? 'Update User' : 'Create User'}
        </Button>
      </Stack>
    </Box>
  );
};

export default UserForm;
