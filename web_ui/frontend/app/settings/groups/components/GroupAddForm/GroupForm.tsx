'use client';

import React, { useState } from 'react';
import { TextField, Button, Box, Stack } from '@mui/material';
import { Group, GroupPost } from '@/types';

type CreateGroupFormProps = {
  group?: undefined;
  onSubmit: (newGroup: Omit<GroupPost, 'id'>) => Promise<void>;
  isSubmitting?: boolean;
};

type UpdateGroupFormProps = {
  group: Group;
  onSubmit: (updatedGroup: GroupPost) => Promise<void>;
  isSubmitting?: boolean;
};

type GroupFormProps = CreateGroupFormProps | UpdateGroupFormProps;

const GroupForm: React.FC<GroupFormProps> = ({
  group,
  onSubmit,
  isSubmitting = false,
}) => {
  const [name, setName] = useState(group?.name || '');
  const [description, setDescription] = useState(group?.description || '');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const response = group
      ? await onSubmit({ id: group.id, name, description })
      : await onSubmit({ name, description });
  };

  return (
    <Box component='form' onSubmit={handleSubmit}>
      <Stack spacing={2}>
        <TextField
          id='name'
          label='Group Name'
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={isSubmitting}
          size='small'
          required
          fullWidth
        />
        <TextField
          id='description'
          label='Description'
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          disabled={isSubmitting}
          size='small'
          required
          fullWidth
          multiline
          minRows={2}
        />
        <Button
          type='submit'
          variant='contained'
          color='primary'
          disabled={isSubmitting}
        >
          {group ? 'Update Group' : 'Create Group'}
        </Button>
      </Stack>
    </Box>
  );
};

export default GroupForm;
