import React, { useMemo, useCallback } from 'react';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';

import { createId } from '../util';

/**
 * Props for simple string-based autocomplete (backwards compatible)
 */
export type SimpleAutocompleteFieldProps<T extends string> = {
  name: string;
  value: T[];
  focused?: boolean;
  onChange: (x: T[]) => void;
  possibleValues: T[];
  freeSolo?: boolean;
};

export type AutocompleteFieldProps<T extends string> = SimpleAutocompleteFieldProps<T>;

/**
 * Simple string-based autocomplete field.
 * For object-based autocomplete with label/value separation, use ObjectAutocompleteField.
 */
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
        renderInput={(params) => (
          <TextField
            {...params}
            id={id}
            label={name}
            variant='outlined'
            size='small'
            autoFocus={!!focused}
          />
        )}
      />
    </div>
  );
}

export default AutocompleteField;
