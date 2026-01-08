import Link from 'next/link';
import { Box, IconButton } from '@mui/material';
import { InfoOutline } from '@mui/icons-material';

import { Group } from '@/types';
import ListCard from '@/components/ListCard';
import CardTitle from '@/components/CardTitle';

interface GroupCardProps {
  group: Group;
}

const GroupCard = ({ group }: GroupCardProps) => {
  return (
    <Link href={`./view/?id=${group.id}`} style={{ textDecoration: 'none' }}>
      <ListCard>
        <CardTitle title={group.name} description={group.description} />
        <Box display={'flex'} alignItems={'center'}>
          <IconButton>
            <InfoOutline />
          </IconButton>
        </Box>
      </ListCard>
    </Link>
  );
};

export default GroupCard;
