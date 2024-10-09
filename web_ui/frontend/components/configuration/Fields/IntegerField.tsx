import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from '@mui/material';
import React, {
  useMemo,
  useCallback,
  SetStateAction,
  ChangeEvent,
  useEffect,
} from 'react';

import { createId, buildPatch } from '../util';

/**
 * Verify if the Integer is in the correct format
 * @param value
 */
const verifyInteger = (value: string): boolean => {
  const regex = new RegExp('^[0-9]+$');
  return regex.test(value);
};

export type IntegerFieldProps = {
  name: string;
  value: number;
  focused?: boolean;
  onChange: (x: number) => void;
};

const IntegerField = ({
  onChange,
  name,
  value,
  focused,
}: IntegerFieldProps) => {
  const id = useMemo(() => createId(name), [name]);

  const [bufferValue, setBufferValue] = React.useState<string>(
    value.toString()
  );

  const error = useMemo(() => {
    return verifyInteger(bufferValue) ? undefined : 'Value must be a integer';
  }, [bufferValue]);

  useEffect(() => {
    setBufferValue(value.toString());
  }, [value]);

  return (
    <TextField
      fullWidth
      size='small'
      id={id}
      label={name}
      variant={'outlined'}
      focused={focused}
      value={bufferValue}
      onChange={(e) => {
        setBufferValue(e.target.value);
        if (verifyInteger(e.target.value)) {
          onChange(parseInt(e.target.value));
        }
      }}
      onBlur={(e) => {
        setBufferValue(value.toString());
      }}
      error={error !== undefined}
      helperText={error}
    />
  );
};

export default IntegerField;
