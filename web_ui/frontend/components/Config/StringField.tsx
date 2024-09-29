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
} from 'react';

import { ParameterInputProps } from '@/components/Config/index';
import { createId, buildPatch } from './util';

export type StringFieldProps = {
  name: string;
  value: string;
  onChange: (a: string) => void;
  verify?: (a: string) => string | undefined;
};

const StringField = ({ onChange, name, value, verify }: StringFieldProps) => {
  const id = useMemo(() => createId(name), [name]);

  const [localValue, setLocalValue] = React.useState<string>(value);
  const [error, setError] = React.useState<string | undefined>(undefined);

  const handleOnChange = useCallback(
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      setLocalValue(event.target.value);

      if (verify !== undefined) {
        if (verify(event.target.value) !== undefined) {
          setError(verify(event.target.value));
        } else {
          setError(undefined);
          onChange(event.target.value);
        }
      } else {
        onChange(event.target.value);
      }
    },
    [onChange]
  );

  return (
    <TextField
      fullWidth
      size='small'
      id={id}
      label={name}
      name={name.toLowerCase()}
      variant={'outlined'}
      focused={value != localValue}
      value={localValue}
      onChange={handleOnChange}
      helperText={error}
      error={error !== undefined}
    />
  );
};

export default StringField;
