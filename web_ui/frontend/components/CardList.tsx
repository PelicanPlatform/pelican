'use client';

import React, {
  ComponentType,
  FunctionComponent,
  useMemo,
  useState,
  JSX,
  useEffect,
} from 'react';
import {
  Box,
  Pagination,
  Skeleton,
  TextField,
  Typography,
} from '@mui/material';

interface CardListProps<T> {
  data?: Partial<T>[];
  Card: ComponentType<any>;
  cardProps?: Partial<T>;
  pageSize?: number;
}

export function CardList<T>({
  data,
  Card,
  cardProps,
  pageSize = 10,
}: CardListProps<T>) {
  const [page, setPage] = useState<number>(1);

  // Minus the page if the data length changes
  useEffect(() => {
    if (data?.length && page > Math.ceil(data.length / pageSize)) {
      setPage(Math.max(1, Math.ceil(data.length / pageSize)));
    }
  }, [data?.length]);

  const count = useMemo(() => {
    return Math.ceil((data?.length || 0) / pageSize);
  }, [data]);

  const slicedObjects = useMemo(() => {
    return (data || []).slice((page - 1) * pageSize, page * pageSize);
  }, [data, page]);

  return (
    <>
      <Box>
        {slicedObjects.map((o, i) => {
          const props = {
            ...cardProps,
            ...o,
          } as T;

          return (
            <Box pb={1} key={JSON.stringify(props)}>
              <Card {...props} />
            </Box>
          );
        })}
        {!data || (count == 0 && <NoResultsCard />)}
      </Box>
      <Box
        display={'flex'}
        justifyContent={'center'}
        flexDirection={'column'}
        alignItems={'center'}
      >
        {count > 1 && (
          <Pagination
            count={count}
            page={page}
            onChange={(e, p) => setPage(p)}
          />
        )}
        <Typography variant={'subtitle1'}>{data?.length || 0} items</Typography>
      </Box>
    </>
  );
}

/**
 * A card to display when there are no results
 * Has the text No results centered in a text box with height 60 and 100% width
 * @constructor
 */
const NoResultsCard = () => {
  return (
    <Box
      height={60}
      display={'flex'}
      justifyContent={'center'}
      alignItems={'center'}
      border={'1px solid grey'}
      borderRadius={1}
    >
      <Typography>No results</Typography>
    </Box>
  );
};

export default CardList;
