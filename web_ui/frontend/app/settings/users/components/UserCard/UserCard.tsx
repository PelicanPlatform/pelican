'use client';

import { useState } from 'react';
import { Box, Badge } from '@mui/material';

import { User } from '@/types';
import ListCard from '@/components/ListCard';
import createdRecently from '@/helpers/createdRecently';

import InformationDropdown from './Dropdown';

interface UserCardProps {
  user: User;
}

const UserCard = ({ user }: UserCardProps) => {
  const [open, setOpen] = useState(false);
  const recentlyAdded = createdRecently(new Date(user.createdAt).getTime());

  return (
    <>
      <Badge
        color='success'
        invisible={!recentlyAdded}
        badgeContent='New'
        sx={{ width: '100%', display: 'block' }}
      >
        <ListCard onClick={() => setOpen(!open)}>
          <Box>{user.username}</Box>
          <Box>{user.createdAt}</Box>
        </ListCard>
        <InformationDropdown user={user} transition={open} />
      </Badge>
    </>
  );
};

export default UserCard;
