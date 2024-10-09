import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  SelectChangeEvent,
  TextField,
} from '@mui/material';
import React, {
  useMemo,
  useCallback,
  SetStateAction,
  ChangeEvent,
} from 'react';
import OutlinedInput from '@mui/material/OutlinedInput';

import { createId, buildPatch } from '../util';

export type MultiSelectFieldProps<T extends string> = {
  name: string;
  value: T[];
  focused?: boolean;
  onChange: (x: T[]) => void;
  possibleValues: T[];
};

function MultiSelectField<T extends string>({
  onChange,
  name,
  value,
  possibleValues,
  focused,
}: MultiSelectFieldProps<T>) {
  const id = useMemo(() => createId(name), [name]);
  const handleChange = (event: SelectChangeEvent<T[]>) => {
    const {
      target: { value },
    } = event;

    const newValue =
      typeof value === 'string' ? (value.split(',') as T[]) : value;
    onChange(newValue);
  };

  return (
    <div>
      <FormControl fullWidth size={'small'} focused={focused}>
        <InputLabel id={id}>Name</InputLabel>
        <Select<T[]>
          labelId='demo-multiple-name-label'
          id='demo-multiple-name'
          multiple
          value={value}
          onChange={handleChange}
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

export default MultiSelectField;
