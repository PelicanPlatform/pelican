'use client';

import React, { ComponentType, useState } from 'react';
import { Box, TextField } from '@mui/material';

import { CardList } from '@/components';
import useFuse from '@/helpers/useFuse';
import { CardProps } from '@/components/Namespace/Card';

interface CardListProps<T> {
  data: Partial<T>[];
  Card: ComponentType<any>;
  cardProps: Partial<T>;
}

function NamespaceCardList<T extends CardProps>({
  data,
  Card,
  cardProps,
}: CardListProps<T>) {
  const [search, setSearch] = useState<string>('');
  const filteredObjects = useFuse<Partial<T>>(data, search);

  return (
    <Box>
      <Box sx={{ pb: 1 }}>
        <TextField
          size={'small'}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          label='Search'
          color={filteredObjects.length == 0 ? 'warning' : 'primary'}
          helperText={
            filteredObjects.length == 0 ? 'No results found' : undefined
          }
        />
      </Box>
      <CardList<T>
        Card={Card}
        cardProps={cardProps}
        data={filteredObjects}
        keyGetter={(o) => o?.namespace?.prefix || 'undefined'}
      />
    </Box>
  );
}

export default NamespaceCardList;
