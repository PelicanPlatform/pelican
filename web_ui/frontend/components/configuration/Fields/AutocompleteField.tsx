import React, { useMemo } from 'react';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import Chip from '@mui/material/Chip';

import { createId } from '../util';

export type AutocompleteFieldProps<T extends string> = {
  name: string;
  value: T[];
  focused?: boolean;
  onChange: (x: T[]) => void;
  possibleValues: T[];
  freeSolo?: boolean;
};

function AutocompleteField<T extends string>({
  onChange,
  name,
  value,
  possibleValues,
  focused,
  freeSolo = false,
}: AutocompleteFieldProps<T>) {
  const id = useMemo(() => createId(name), [name]);

  return (
    <div>
      <Autocomplete
        multiple
        freeSolo={freeSolo}
        options={possibleValues}
        value={value}
        onChange={(_, newValue) => onChange(newValue as T[])}
        getOptionLabel={(option) => option}
        renderValue={(tagValue, getValueProps) =>
          tagValue.map((option, index) => {
            const {key, ...tagProps} = getValueProps({ index });
            return <Chip key={key} label={option} {...tagProps} />;
          })
        }
        renderInput={(params) => (
          <TextField
            {...params}
            id={id}
            label={name}
            variant="outlined"
            size="small"
            autoFocus={!!focused}
          />
        )}
      />
    </div>
  );
}

export default AutocompleteField;
