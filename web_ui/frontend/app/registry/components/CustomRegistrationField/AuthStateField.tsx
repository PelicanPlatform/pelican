import {
  Autocomplete,
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  FormGroup,
  FormHelperText,
  IconButton,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import React, { useMemo } from 'react';

import { createId } from '@/components/configuration/util';
import type {
  Capabilities,
  NamespaceAuthState,
  TokenGeneration,
  TokenIssuer,
} from '@/types';
import type { BaseCustomRegistrationFieldProps } from './index';

// One checkbox per capability flag, keyed and labelled the way the director's
// namespace view shows them so a state can be copied across by eye
const CAPABILITY_FLAGS: {
  key: keyof Capabilities;
  label: string;
  hint: string;
}[] = [
  {
    key: 'PublicRead',
    label: 'Public reads',
    hint: 'Objects can be read without a token (implies reads)',
  },
  { key: 'Read', label: 'Reads', hint: 'Objects can be read with a token' },
  {
    key: 'Write',
    label: 'Writes',
    hint: 'Objects can be written with a token',
  },
  { key: 'Listing', label: 'Listings', hint: 'Collections can be listed' },
  {
    key: 'FallBackRead',
    label: 'Direct reads',
    hint: 'Clients may read from an origin directly when no cache serves them',
  },
];

export const emptyAuthState = (): NamespaceAuthState => ({
  capabilities: {
    PublicRead: false,
    Read: true,
    Write: false,
    Listing: false,
    FallBackRead: false,
  },
  tokenGeneration: [],
  tokenIssuer: [],
});

const emptyIssuer = (): TokenIssuer => ({
  issuer: '',
  basePaths: [],
  restrictedPaths: [],
});

const emptyGeneration = (): TokenGeneration => ({
  strategy: 'OAuth2',
  vaultServer: '',
  maxScopeDepth: 3,
  issuer: '',
});

/**
 * A list of absolute paths entered one at a time, shown as chips
 */
const PathListInput = ({
  label,
  helperText,
  placeholder,
  value,
  disabled,
  onChange,
}: {
  label: string;
  helperText: string;
  placeholder: string;
  value: string[];
  disabled?: boolean;
  onChange: (paths: string[]) => void;
}) => (
  <Autocomplete
    multiple
    freeSolo
    size='small'
    disabled={disabled}
    options={[]}
    value={value}
    onChange={(e, paths) => onChange(paths as string[])}
    renderInput={(params) => (
      <TextField
        {...params}
        label={label}
        helperText={helperText}
        placeholder={value.length ? '' : placeholder}
      />
    )}
    sx={{ flex: 2, minWidth: 0 }}
  />
);

/**
 * Edits a registration's auth state: off means the namespace is advertised
 * only while an origin serves it; on, the registry advertises it itself with
 * the capabilities, token issuers and token generation entered here
 */
const AuthStateField = ({
  onChange,
  displayed_name,
  name,
  description,
  value,
  disabled,
}: BaseCustomRegistrationFieldProps<NamespaceAuthState>) => {
  const id = useMemo(() => createId(name), [name]);

  // The API returns null for a registration without one
  const enabled = value !== undefined && value !== null;
  const state: NamespaceAuthState = enabled ? value : emptyAuthState();
  const issuers = state.tokenIssuer ?? [];
  const generations = state.tokenGeneration ?? [];

  const update = (patch: Partial<NamespaceAuthState>) =>
    onChange({ ...state, ...patch });

  const setIssuer = (index: number, issuer: TokenIssuer) =>
    update({
      tokenIssuer: issuers.map((it, i) => (i === index ? issuer : it)),
    });
  const removeIssuer = (index: number) =>
    update({ tokenIssuer: issuers.filter((_, i) => i !== index) });

  const setGeneration = (index: number, generation: TokenGeneration) =>
    update({
      tokenGeneration: generations.map((it, i) =>
        i === index ? generation : it
      ),
    });
  const removeGeneration = (index: number) =>
    update({ tokenGeneration: generations.filter((_, i) => i !== index) });

  return (
    <Box>
      <FormControlLabel
        control={
          <Switch
            id={id}
            name={name}
            checked={enabled}
            disabled={disabled}
            onChange={(e) =>
              onChange(e.target.checked ? emptyAuthState() : null)
            }
          />
        }
        label={displayed_name}
      />
      <FormHelperText>{description}</FormHelperText>
      {enabled && (
        <Box
          sx={{
            border: '1px solid',
            borderColor: 'divider',
            borderRadius: 1,
            p: 2,
            mt: 1,
          }}
        >
          <Typography variant={'subtitle2'}>Capabilities</Typography>
          <FormGroup row>
            {CAPABILITY_FLAGS.map((flag) => (
              <Tooltip key={flag.key} title={flag.hint}>
                <FormControlLabel
                  label={flag.label}
                  control={
                    <Checkbox
                      size='small'
                      checked={state.capabilities?.[flag.key] ?? false}
                      disabled={disabled}
                      onChange={(e) =>
                        update({
                          capabilities: {
                            ...state.capabilities,
                            [flag.key]: e.target.checked,
                          },
                        })
                      }
                    />
                  }
                />
              </Tooltip>
            ))}
          </FormGroup>

          <Typography variant={'subtitle2'} sx={{ mt: 2 }}>
            Token issuers
          </Typography>
          <FormHelperText>
            The issuers whose tokens caches accept for this namespace. Each base
            path must be the registered prefix or lie under it; a restricted
            path must lie under one of the base paths.
          </FormHelperText>
          {issuers.map((issuer, index) => (
            <Stack
              key={index}
              direction={{ xs: 'column', md: 'row' }}
              spacing={1}
              alignItems={'flex-start'}
              sx={{ mt: 1 }}
            >
              <TextField
                size='small'
                label={'Issuer URL'}
                helperText={'An https URL'}
                placeholder={'https://issuer.example.org'}
                value={issuer.issuer}
                disabled={disabled}
                onChange={(e) =>
                  setIssuer(index, { ...issuer, issuer: e.target.value })
                }
                sx={{ flex: 2, minWidth: 0 }}
              />
              <PathListInput
                label={'Base paths'}
                helperText={'Type a path and press Enter'}
                placeholder={'/foo/bar'}
                value={issuer.basePaths ?? []}
                disabled={disabled}
                onChange={(basePaths) =>
                  setIssuer(index, { ...issuer, basePaths })
                }
              />
              <PathListInput
                label={'Restricted paths'}
                helperText={'Optional'}
                placeholder={'/foo/bar/private'}
                value={issuer.restrictedPaths ?? []}
                disabled={disabled}
                onChange={(restrictedPaths) =>
                  setIssuer(index, { ...issuer, restrictedPaths })
                }
              />
              <Tooltip title={'Remove issuer'}>
                <span>
                  <IconButton
                    size='small'
                    disabled={disabled}
                    onClick={() => removeIssuer(index)}
                  >
                    <Delete fontSize='small' />
                  </IconButton>
                </span>
              </Tooltip>
            </Stack>
          ))}
          <Button
            size='small'
            startIcon={<Add />}
            disabled={disabled}
            onClick={() => update({ tokenIssuer: [...issuers, emptyIssuer()] })}
            sx={{ mt: 1 }}
          >
            Add issuer
          </Button>

          <Typography variant={'subtitle2'} sx={{ mt: 2 }}>
            Token generation
          </Typography>
          <FormHelperText>
            How a client obtains a token for this namespace: an OAuth2 flow
            against the issuer, the only strategy the Pelican client implements.
          </FormHelperText>
          {generations.map((generation, index) => {
            return (
              <Stack
                key={index}
                direction={{ xs: 'column', md: 'row' }}
                spacing={1}
                alignItems={'flex-start'}
                sx={{ mt: 1 }}
              >
                <TextField
                  size='small'
                  label={'Issuer URL'}
                  helperText={'An https URL'}
                  placeholder={'https://issuer.example.org'}
                  value={generation.issuer}
                  disabled={disabled}
                  onChange={(e) =>
                    setGeneration(index, {
                      ...generation,
                      issuer: e.target.value,
                    })
                  }
                  sx={{ flex: 2, minWidth: 0 }}
                />
                <TextField
                  size='small'
                  type='number'
                  label={'Max scope depth'}
                  value={generation.maxScopeDepth}
                  disabled={disabled}
                  slotProps={{ htmlInput: { min: 0 } }}
                  onChange={(e) =>
                    setGeneration(index, {
                      ...generation,
                      maxScopeDepth: Math.max(0, parseInt(e.target.value) || 0),
                    })
                  }
                  sx={{ width: 140 }}
                />
                <Tooltip title={'Remove'}>
                  <span>
                    <IconButton
                      size='small'
                      disabled={disabled}
                      onClick={() => removeGeneration(index)}
                    >
                      <Delete fontSize='small' />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            );
          })}
          <Button
            size='small'
            startIcon={<Add />}
            disabled={disabled}
            onClick={() =>
              update({ tokenGeneration: [...generations, emptyGeneration()] })
            }
            sx={{ mt: 1 }}
          >
            Add token generation
          </Button>
        </Box>
      )}
    </Box>
  );
};

export default AuthStateField;
export { AuthStateField };
