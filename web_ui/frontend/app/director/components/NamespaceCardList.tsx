import React, {
  useState
} from 'react';
import { Box, TextField } from '@mui/material';
import { NamespaceCard, NamespaceCardProps } from './';
import { CardList } from '@/components';
import useFuse from '@/helpers/useFuse';

interface NamespaceCardListProps {
  data?: Partial<NamespaceCardProps>[];
}

export function NamespaceCardList({ data }: NamespaceCardListProps) {
  const [search, setSearch] = useState<string>('');

  const searchedData = useFuse<Partial<NamespaceCardProps>>(data || [], search);

  return (
    <Box>
      <Box sx={{ pb: 1 }}>
        <TextField
          size={'small'}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          label='Search'
        />
      </Box>
      <CardList data={searchedData} Card={NamespaceCard} />
    </Box>
  );
}

export default NamespaceCardList;
