import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  SelectChangeEvent,
  TextField,
  Box,
  Tooltip,
  IconButton,
  Typography,
} from '@mui/material';
import {
  KeyboardArrowDown,
  KeyboardArrowUp,
  KeyboardDoubleArrowDown,
  Edit,
  Close,
} from '@mui/icons-material';
import React, { useMemo, useCallback, ChangeEvent, KeyboardEvent } from 'react';

import { ParameterInputProps } from '@/components/Config/index.d';
import { createId, buildPatch, stringSort } from './util';

interface StringSliceCardProps {
  value: string;
  onClick: () => void;
}

const StringSliceCard = ({ value, onClick }: StringSliceCardProps) => {
  return (
    <Box
      sx={{
        borderRadius: '4px',
        marginTop: '0.1rem',
        padding: '0.1rem 0.5rem',
        display: 'flex',
        justifyContent: 'space-between',
        cursor: 'pointer',
        borderWidth: '2px',
        borderStyle: 'solid',
        borderColor: 'transparent',
        '&:hover': {
          borderColor: 'primary.light',
        },
      }}
      onClick={onClick}
    >
      <Box
        sx={{
          overflowX: 'auto',
          my: 'auto',
        }}
      >
        {value}
      </Box>
      <IconButton size={'small'}>
        <Close />
      </IconButton>
    </Box>
  );
};

export type StringSliceFieldProps = {
  name: string;
  value: string[];
  onChange: (value: string[]) => void;
};

const StringSliceField = ({ onChange, name, value }: StringSliceFieldProps) => {
  const id = useMemo(() => createId(name), [name]);
  const startingState = useMemo(() => (value == null ? [] : value), [value]);

  const [localValue, setLocalValue] = React.useState<string[]>(startingState);
  const [inputValue, setInputValue] = React.useState<string>('');

  const [dropdownHeight, setDropdownHeight] = React.useState<
    string | undefined
  >('0px');

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (
        event.key == 'Enter' &&
        event.target instanceof HTMLInputElement &&
        event.target.value != ''
      ) {
        const newValue = [
          ...new Set<string>([...localValue, event.target.value]),
        ].sort(stringSort);

        setLocalValue(newValue);
        onChange(newValue);
        setInputValue('');
      }
    },
    [onChange, inputValue]
  );

  const handleOnChange = useCallback(
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      setInputValue(event.target.value);
    },
    []
  );

  return (
    <>
      <TextField
        fullWidth
        size='small'
        id={id}
        label={name}
        variant={'outlined'}
        value={inputValue}
        focused={localValue.toString() != startingState.toString()}
        helperText={inputValue == '' ? undefined : 'Press enter to add'}
        onChange={handleOnChange}
        InputProps={{ onKeyDown: handleKeyDown }}
      />
      <Box>
        {localValue.length > 0 && (
          <Box
            sx={{
              display: 'flex',
              borderRadius: 1,
              border: '1px solid #c4c4c4',
            }}
          >
            <Box mx={'auto'}>
              <Tooltip title={'Minimize'}>
                <IconButton
                  size='small'
                  onClick={() => setDropdownHeight('0px')}
                >
                  <KeyboardArrowUp />
                </IconButton>
              </Tooltip>
              <Tooltip title={'Scroll View'}>
                <IconButton
                  size='small'
                  onClick={() => setDropdownHeight('10rem')}
                >
                  <KeyboardArrowDown />
                </IconButton>
              </Tooltip>
              <Tooltip title={'Maximize'}>
                <IconButton
                  size='small'
                  onClick={() => setDropdownHeight('auto')}
                >
                  <KeyboardDoubleArrowDown />
                </IconButton>
              </Tooltip>
              <Box ml={1} display={'inline'}>
                <Typography variant={'caption'}>
                  {localValue.length} Items
                </Typography>
              </Box>
            </Box>
          </Box>
        )}
        <Box
          sx={{
            maxHeight: dropdownHeight,
            overflowY: 'scroll',
            borderBottom:
              localValue.length == 0 || dropdownHeight == '0px'
                ? undefined
                : 'black 1px solid',
          }}
        >
          {localValue.map((val) => {
            return (
              <StringSliceCard
                key={val}
                value={val}
                onClick={() => {
                  const newValue = localValue.filter((v) => v != val);
                  setLocalValue(newValue);
                  onChange(buildPatch(name, newValue));
                  setInputValue(val);
                }}
              />
            );
          })}
        </Box>
      </Box>
    </>
  );
};

export default StringSliceField;
