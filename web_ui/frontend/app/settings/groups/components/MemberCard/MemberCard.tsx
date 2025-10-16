import { Badge, Box } from '@mui/material';
import { useContext, useState } from 'react';
import { Delete } from '@mui/icons-material';

import { ConfirmButton } from '@chtc/web-components';

import { GroupMember } from '@/types';
import ListCard from '@/components/ListCard';
import { alertOnError } from '@/helpers/util';
import { fetchApi } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { useSWRConfig } from 'swr';
import CardTitle from '@/components/CardTitle';
import InformationDropdown from './Dropdown';
import createdRecently from '@/helpers/createdRecently';

interface MemberCardProps {
  member: GroupMember;
}

const MemberCard = ({ member }: MemberCardProps) => {
  const [open, setOpen] = useState(false);

  const dispatch = useContext(AlertDispatchContext);
  const { mutate } = useSWRConfig();

  const recentlyAdded = createdRecently(new Date(member.createdAt).getTime());

  return (
    <Badge
      badgeContent={'New'}
      invisible={!recentlyAdded}
      sx={{ display: 'block' }}
      color='success'
    >
      <ListCard
        onClick={() => setOpen(!open)}
        sx={{
          cursor: 'pointer',
        }}
      >
        <CardTitle
          title={member?.user?.username}
          description={member.createdAt}
        />
        <Box>
          <ConfirmButton
            sx={{ bgcolor: '#ff00001a', mx: 1 }}
            color={'error'}
            onClick={(e) => e.stopPropagation()}
            confirmNode={'Delete'}
            onConfirm={async (e) => {
              e.stopPropagation();
              await alertOnError(
                async () => await removeMember(member.groupId, member.user.id),
                'Could Not Delete Registration',
                dispatch
              );
              await mutate(`/api/v1.0/groups/${member.groupId}/members`);
            }}
          >
            <Delete />
          </ConfirmButton>
        </Box>
      </ListCard>
      <InformationDropdown member={member} transition={open} />
    </Badge>
  );
};

const removeMember = async (groupId: string, userId: string) => {
  return fetchApi(async () =>
    fetch(`/api/v1.0/groups/${groupId}/members/${userId}`, { method: 'DELETE' })
  );
};

export default MemberCard;
