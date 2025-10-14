import React from 'react';
import { Box } from '@mui/material';
import { Dropdown, InformationSpan } from '@/components';
import { Group } from '@/types';

interface InformationDropdownProps {
  group: Group;
  transition: boolean;
}

const InformationDropdown = ({
  group,
  transition,
}: InformationDropdownProps) => {
  const information = [
    { name: 'Group ID', value: group.id },
    { name: 'Name', value: group.name },
    { name: 'Description', value: group.description },
    { name: 'Created By', value: group.createdBy },
    { name: 'Created At', value: new Date(group.createdAt).toLocaleString() },
    { name: 'Members', value: group.members.length.toString() },
  ];

  return (
    <Dropdown transition={transition}>
      <Box>
        {information.map((info) => (
          <InformationSpan key={info.name} {...info} />
        ))}
      </Box>
    </Dropdown>
  );
};

export default InformationDropdown;
