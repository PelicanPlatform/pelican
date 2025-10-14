import React from 'react';
import { Box } from '@mui/material';
import { Dropdown, InformationSpan } from '@/components';
import { User } from '@/types';

interface InformationDropdownProps {
  user: User;
  transition: boolean;
}

const InformationDropdown = ({
  user,
  transition,
}: InformationDropdownProps) => {
  const information = [
    { name: 'User ID', value: user.id },
    { name: 'Username', value: user.username },
    { name: 'Subject', value: user.sub },
    { name: 'Issuer', value: user.issuer },
    { name: 'Created At', value: new Date(user.createdAt).toLocaleString() },
  ];

  return (
    <Dropdown transition={transition}>
      <Box width={'100%'}>
        {information.map((info) => (
          <InformationSpan key={info.name} {...info} />
        ))}
      </Box>
    </Dropdown>
  );
};

export default InformationDropdown;
