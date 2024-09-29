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

import { ParameterInputProps } from '@/components/Config/index';
import { createId, buildPatch } from './util';
import OutlinedInput from '@mui/material/OutlinedInput';

export type MultiSelectFieldProps<T extends string> = {
  name: string;
  value: T[];
  onChange: (x: T[]) => void;
  possibleValues: T[];
};

function MultiSelectField<T extends string>({
  onChange,
  name,
  value,
  possibleValues,
}: MultiSelectFieldProps<T>) {
  const id = useMemo(() => createId(name), [name]);

  const [localValue, setLocalValue] = React.useState<T[]>(value);

  const handleChange = (event: SelectChangeEvent<T[]>) => {
    const {
      target: { value },
    } = event;

    const newValue =
      typeof value === 'string' ? (value.split(',') as T[]) : value;
    setLocalValue(newValue);
    onChange(newValue);
  };

  return (
    <div>
      <FormControl fullWidth size={'small'} focused={value != localValue}>
        <InputLabel id={id}>Name</InputLabel>
        <Select<T[]>
          labelId='demo-multiple-name-label'
          id='demo-multiple-name'
          multiple
          value={localValue}
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
