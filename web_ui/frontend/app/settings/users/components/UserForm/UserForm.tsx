'use client';

import React, { useState } from 'react';
import { TextField, Button, Box, Alert, Stack } from '@mui/material';

import { User, UserPatch, UserPost } from '@/types';

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

const UserForm: React.FC<UserFormProps> = ({
  user,
  onSubmit,
  isSubmitting = false,
}) => {
  const [username, setUsername] = useState(user?.username || '');
  const [sub, setSub] = useState(user?.sub || '');
  const [issuer, setIssuer] = useState(user?.issuer || '');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (user) {
      await onSubmit({
        id: user?.id,
        username,
        sub,
        issuer,
      });
    } else {
      await onSubmit({
        username,
        sub,
        issuer,
      });
    }
  };

  return (
    <Box component='form' onSubmit={handleSubmit}>
      <Stack spacing={2}>
        <TextField
          id='username'
          label='Username'
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={isSubmitting}
          size={'small'}
          required
          fullWidth
        />
        <TextField
          id='sub'
          label='Sub'
          value={sub}
          onChange={(e) => setSub(e.target.value)}
          disabled={isSubmitting}
          size={'small'}
          required
          fullWidth
        />
        <TextField
          id='issuer'
          label='Issuer'
          value={issuer}
          onChange={(e) => setIssuer(e.target.value)}
          disabled={isSubmitting}
          size={'small'}
          required
          fullWidth
        />
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
