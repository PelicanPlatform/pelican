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

import { ParameterInputProps, Duration } from '@/components/Config/index';
import { createId, buildPatch } from './util';

export type VerifiableParameter = ParameterInputProps & {
  Value: string;
  verify: (value: string) => boolean;
};

const VerifiableField = ({
  onChange,
  verify,
  name,
  description,
  components,
  Value,
}: VerifiableParameter) => {
  const id = useMemo(() => createId(name), [name]);

  const [value, setValue] = React.useState<string>(Value);
  const [error, setError] = React.useState<string | undefined>(undefined);

  const handleOnChange = useCallback(
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      if (!verify(event.target.value)) {
        setError('Invalid duration format');
      } else {
        setError(undefined);
      }

      setValue(event.target.value);
      onChange(buildPatch(name, event.target.value));
    },
    [onChange]
  );

  return (
    <TextField
      fullWidth
      size='small'
      id={id}
      label={name}
      variant={'outlined'}
      focused={value != Value}
      value={value}
      onChange={handleOnChange}
      error={error !== undefined}
      helperText={error}
    />
  );
};

export default VerifiableField;
