import React from 'react';
import { Box } from '@mui/material';
import { Dropdown, InformationSpan } from '@/components';
import { GroupMember } from '@/types';

interface InformationDropdownProps {
  member: GroupMember;
  transition: boolean;
}

const InformationDropdown = ({
  member,
  transition,
}: InformationDropdownProps) => {
  const information = [
    { name: 'Added By', value: member.createdBy },
    { name: 'Added At', value: new Date(member.createdAt).toLocaleString() },
    { name: 'User Internal ID', value: member.user.id },
    { name: 'Username', value: member.user.username },
    { name: 'Subject', value: member.user.sub },
    { name: 'Issuer', value: member.user.issuer },
    {
      name: 'User Created At',
      value: new Date(member.user.createdAt).toLocaleString(),
    },
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
