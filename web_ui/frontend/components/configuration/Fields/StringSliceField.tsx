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
import React, {
  useMemo,
  useCallback,
  ChangeEvent,
  KeyboardEvent,
  useEffect,
} from 'react';

import { createId, buildPatch, stringSort } from '../util';

export type StringSliceFieldProps = {
  name: string;
  value: string[];
  focused?: boolean;
  onChange: (value: string[]) => void;
  verify?: (value: string[]) => string | undefined;
};

const StringSliceField = ({
  onChange,
  name,
  value,
  focused,
  verify,
}: StringSliceFieldProps) => {
  const id = useMemo(() => createId(name), [name]);

  // Hold a buffer value so that you can type freely without saving an invalid state
  const [bufferValue, setBufferValue] = React.useState(value || []);
  useEffect(() => {
    setBufferValue(value || []);
  }, [value]);

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
          ...new Set<string>([event.target.value, ...bufferValue]),
        ];

        setBufferValue(newValue);
        setInputValue('');

        if (verify && verify(newValue) !== undefined) {
          return;
        }

        onChange(newValue);
      }
    },
    [onChange, inputValue]
  );

  const error = useMemo(
    () => (verify ? verify(bufferValue) : undefined),
    [bufferValue]
  );

  const helperText = useMemo(() => {
    if (error) {
      return error;
    } else if (inputValue != '') {
      return 'Press enter to add';
    }
  }, [error, inputValue]);

  return (
    <>
      <TextField
        fullWidth
        size='small'
        id={id}
        label={name}
        variant={'outlined'}
        value={inputValue}
        focused={focused}
        helperText={helperText}
        onChange={(e) => setInputValue(e.target.value)}
        InputProps={{ onKeyDown: handleKeyDown }}
        error={error !== undefined}
      />
      <Box>
        {bufferValue.length > 0 && (
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
                  {bufferValue.length} Items
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
              bufferValue.length == 0 || dropdownHeight == '0px'
                ? undefined
                : 'black 1px solid',
          }}
        >
          {bufferValue.map((val) => {
            return (
              <StringSliceCard
                key={val}
                value={val}
                onDelete={() => {
                  const newValue = bufferValue.filter((v) => v != val);
                  onChange(newValue);
                  setInputValue(val);
                }}
                onMoveUp={() => {
                  const index = bufferValue.indexOf(val);
                  if (index > 0) {
                    const newValue = [...bufferValue];
                    [newValue[index - 1], newValue[index]] = [
                      newValue[index],
                      newValue[index - 1],
                    ];
                    onChange(newValue);
                  }
                }}
                onMoveDown={() => {
                  const index = bufferValue.indexOf(val);
                  if (index < bufferValue.length - 1) {
                    const newValue = [...bufferValue];
                    [newValue[index + 1], newValue[index]] = [
                      newValue[index],
                      newValue[index + 1],
                    ];
                    onChange(newValue);
                  }
                }}
              />
            );
          })}
        </Box>
      </Box>
    </>
  );
};

interface StringSliceCardProps {
  value: string;
  onDelete: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}

const StringSliceCard = ({
  value,
  onDelete,
  onMoveDown,
  onMoveUp,
}: StringSliceCardProps) => {
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
    >
      <Box
        sx={{
          overflowX: 'auto',
          my: 'auto',
        }}
      >
        {value}
      </Box>
      <Box>
        <Tooltip title={'Move Up'} onClick={onMoveUp}>
          <IconButton size={'small'}>
            <KeyboardArrowUp />
          </IconButton>
        </Tooltip>
        <Tooltip title={'Move Down'}>
          <IconButton size={'small'} onClick={onMoveDown}>
            <KeyboardArrowDown />
          </IconButton>
        </Tooltip>
        <IconButton size={'small'} onClick={onDelete}>
          <Close />
        </IconButton>
      </Box>
    </Box>
  );
};

export default StringSliceField;
