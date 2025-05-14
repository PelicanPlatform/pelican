'use client';

/**
 * TokenList.tsx
 *
 * List component for displaying tokens
 */

import {
  Box,
  Chip,
  IconButton,
  Paper,
  Tooltip,
  Typography,
} from '@mui/material';
import { Delete } from '@mui/icons-material';

import {
  AlertDispatchContext,
  AlertReducerAction,
} from '@/components/AlertProvider';
import { Dispatch, useContext } from 'react';
import useSWR from 'swr';
import { alertOnError } from '@/helpers/util';
import { secureFetch } from '@/helpers/login';
import { fetchApi } from '@/helpers/api';
import { CardList } from '@/components';
import { GetToken } from '@/types';

const TokenList = () => {
  const dispatch = useContext(AlertDispatchContext);

  const { data, mutate } = useSWR<GetToken[]>(
    'getTokens',
    () => alertOnError(getTokens, 'Failed to load tokens', dispatch),
    {
      fallbackData: [],
    }
  );

  return (
    <CardList<TokenCardProps>
      Card={TokenCard}
      data={data?.map((t) => {
        return { token: t };
      })} // Nest token in a object as token key to align with card props
      cardProps={{ mutate, dispatch }}
      pageSize={5}
      keyGetter={(o) => o.token.id}
    />
  );
};

interface TokenCardProps {
  token: GetToken;
  mutate: Function;
  dispatch: Dispatch<AlertReducerAction>;
}

const TokenCard = ({ token, mutate, dispatch }: TokenCardProps) => {
  const expirationDate = new Date(token.expiration);

  return (
    <Paper elevation={1}>
      <Box display={'flex'}>
        <Box
          display={'flex'}
          flexGrow={1}
          flexDirection={'column'}
          mx={1}
          my={0.5}
        >
          <Box>
            <Box display={'flex'}>
              <Typography>{token.name}</Typography>
            </Box>
            <Box display={'flex'}>
              <Typography variant={'subtitle2'}>
                Expires on {expirationDate.toLocaleString()}
              </Typography>
              <Box mx={1}>-</Box>
              <Typography variant={'subtitle2'}>
                Created by {token.createdBy}
              </Typography>
            </Box>
          </Box>
          <Box mt={0.5}>
            {token.scopes.map((x) => {
              return (
                <Tooltip key={x} title={'Token Scope'}>
                  <Chip sx={{ mr: 1 }} size={'small'} label={x} />
                </Tooltip>
              );
            })}
          </Box>
        </Box>
        <Box display={'flex'} ml={'auto'}>
          <IconButton
            size={'small'}
            color={'error'}
            onClick={() => deleteToken(token.id, mutate, dispatch)}
          >
            <Delete />
          </IconButton>
        </Box>
      </Box>
    </Paper>
  );
};

const deleteToken = async (
  id: string,
  mutate: Function,
  dispatch: Dispatch<AlertReducerAction>
) => {
  const r = await alertOnError(
    async () =>
      await fetchApi(() =>
        secureFetch(`/api/v1.0/tokens/${id}`, {
          method: 'DELETE',
        })
      ),
    'Failed to delete token',
    dispatch
  );

  // If the request was successful, update the list of tokens
  if (r !== undefined) {
    mutate();
  }
};

const getTokens = async () => {
  return (await fetchApi(() => secureFetch('/api/v1.0/tokens'))).json();
};

export default TokenList;
