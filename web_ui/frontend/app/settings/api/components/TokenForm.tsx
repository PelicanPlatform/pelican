'use client';

import {
  useState,
  Dispatch,
  useContext,
  useCallback,
  SetStateAction,
} from 'react';
import {
  Autocomplete,
  Box,
  Button,
  IconButton,
  Modal,
  Paper,
  TextField,
  Typography,
} from '@mui/material';
import {
  AlertDispatchContext,
  AlertReducerAction,
} from '@/components/AlertProvider';
import { secureFetch } from '@/helpers/login';
import { fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import Link from 'next/link';
import { BaseToken } from '@/types';
import { Check, ContentCopy, Close } from '@mui/icons-material';

const TokenForm = () => {
  const dispatch = useContext(AlertDispatchContext);

  const [name, setName] = useState('');
  const [createdBy, setCreatedBy] = useState('');
  const [expiration, setExpiration] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [token, setToken] = useState<string | undefined>(undefined);

  const onSubmit = useCallback(async () => {
    const tokenRequest = {
      name,
      createdBy,
      expiration: new Date(expiration).toISOString(),
      scopes,
    };

    const token = await handleSubmit(tokenRequest, dispatch);

    // Remove current fields
    setName('');
    setCreatedBy('');
    setExpiration('');
    setScopes([]);

    return token;
  }, [name, createdBy, expiration, scopes]);

  return (
    <Box sx={{ mt: 3 }}>
      <TextField
        label='Token Name'
        size={'small'}
        fullWidth
        required
        margin={'dense'}
        name={'name'}
        onChange={(e) => setName(e.target.value)}
        value={name}
      />
      <TextField
        label='Creators Name'
        size={'small'}
        fullWidth
        required
        margin={'dense'}
        name={'createdBy'}
        onChange={(e) => setCreatedBy(e.target.value)}
        value={createdBy}
      />
      <TextField
        label='Expiration Date'
        type='date'
        size={'small'}
        fullWidth
        required
        margin={'dense'}
        name={'expiration'}
        InputLabelProps={{
          shrink: true,
        }}
        onChange={(e) => setExpiration(e.target.value)}
        value={expiration}
      />
      <Autocomplete
        multiple
        freeSolo
        options={['monitoring.scrape', 'monitoring.query']}
        id='tags-outlined'
        filterSelectedOptions
        renderInput={(params) => (
          <TextField
            {...params}
            label='Scopes'
            placeholder=''
            size={'small'}
            margin={'dense'}
            name={'scopes'}
            helperText={
              <p>
                All valid scopes can be found on{' '}
                <a
                  target={'_blank'}
                  href={
                    'https://github.com/PelicanPlatform/pelican/blob/main/token_scopes/token_scopes.go'
                  }
                >
                  <span
                    style={{ display: 'inline', textDecoration: 'underline' }}
                  >
                    Github
                  </span>
                </a>
              </p>
            }
          />
        )}
        onChange={(e, value) => setScopes(value)}
        value={scopes}
      />
      <Button
        onClick={async () => setToken(await onSubmit())}
        type='submit'
        variant='contained'
        color='primary'
        sx={{ mt: 2 }}
      >
        Create Token
      </Button>
      <TokenModal setToken={setToken} token={token} />
    </Box>
  );
};

const TokenModal = ({
  token,
  setToken,
}: {
  token?: string;
  setToken: Dispatch<SetStateAction<string | undefined>>;
}) => {
  const [confirmation, setConfirmation] = useState(false);

  return (
    <Modal
      open={token !== undefined}
      onClose={() => setToken(undefined)}
      aria-labelledby='api-token'
      aria-describedby='api-token-viewbox'
    >
      <Box
        sx={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          boxShadow: 24,
          py: 2,
          px: 3,
          borderRadius: 1,
          bgcolor: 'white',
          maxWidth: '100vw',
        }}
      >
        <Box display={'flex'}>
          <Typography variant={'subtitle1'}>
            Copy your API Token, you cannot view it again.
          </Typography>
          <IconButton
            sx={{ ml: 'auto' }}
            size={'small'}
            onClick={() => setToken(undefined)}
          >
            <Close />
          </IconButton>
        </Box>
        <Box
          sx={{
            fontWeight: 500,
            display: 'flex',
            borderRadius: 1,
            bgcolor: '#f5f5f5',
            p: 1,
            pl: 0,
            mt: 2,
            cursor: 'copy',
          }}
          onClick={() => {
            if (token === undefined) return;
            navigator.clipboard.writeText(token);
            setConfirmation(true);
            setTimeout(() => setConfirmation(false), 2000);
          }}
        >
          <IconButton sx={{ mr: 1, my: 'auto' }}>
            {confirmation ? <Check /> : <ContentCopy />}
          </IconButton>
          <Box my={'auto'}>{token}</Box>
        </Box>
      </Box>
    </Modal>
  );
};

const handleSubmit = async (
  token: BaseToken,
  dispatch: Dispatch<AlertReducerAction>
): Promise<string> => {
  const response = await alertOnError(
    async () =>
      await fetchApi(() =>
        secureFetch('/api/v1.0/tokens', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(token),
        })
      ),
    'Failed to create token',
    dispatch
  );

  if (response !== undefined) {
    return (await response.json())['token'];
  }

  return '';
};

export default TokenForm;
