import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  SelectChangeEvent,
  TextField,
} from '@mui/material';
import React, { useMemo } from 'react';

import { createId } from '../util';
import OutlinedInput from '@mui/material/OutlinedInput';

export type SelectFieldProps<T extends string> = {
  name: string;
  value: T;
  focused?: boolean;
  onChange: (x: T) => void;
  possibleValues: T[];
};

function SelectField<T extends string>({
  onChange,
  name,
  value,
  focused,
  possibleValues,
}: SelectFieldProps<T>) {
  const id = useMemo(() => createId(name), [name]);

  return (
    <div>
      <FormControl size={'small'} focused={focused} fullWidth>
        <InputLabel id={`${id}-label`}>{name}</InputLabel>
        <Select<T>
          labelId={`${id}-label`}
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value as T)}
          input={<OutlinedInput label='Name' />}
        >
          {possibleValues.map((v) => (
            <MenuItem key={v} value={v}>
              {v}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    </div>
  );
}

export default SelectField;
