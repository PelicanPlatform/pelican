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

/**
 * Props for object-based autocomplete with label/value separation.
 * Use this when you want to display one field (e.g., username) but save another (e.g., id).
 *
 * Note: freeSolo is not supported for ObjectAutocompleteField as free-form text
 * doesn't have a corresponding object to extract a value from.
 *
 * @template TOption - The type of objects in possibleValues (e.g., User)
 * @template TValue - The type of the saved value (e.g., string for user ID)
 */
export type ObjectAutocompleteFieldProps<TOption, TValue> = {
  name: string;
  value: TValue[];
  focused?: boolean;
  onChange: (x: TValue[]) => void;
  possibleValues: TOption[];
  /** Extract the display label from an option */
  getOptionLabel: (option: TOption) => string;
  /** Extract the value to save from an option */
  getOptionValue: (option: TOption) => TValue;
  /** Find the option that matches a saved value (for displaying saved values) */
  findOption: (value: TValue, options: TOption[]) => TOption | undefined;
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

/**
 * Object-based autocomplete field with label/value separation.
 * Shows human-readable labels but saves different values (e.g., IDs).
 *
 * @example
 * ```tsx
 * <ObjectAutocompleteField<User, string>
 *   name="Users"
 *   possibleValues={users}
 *   value={selectedUserIds}
 *   getOptionLabel={(user) => user.username}
 *   getOptionValue={(user) => user.id}
 *   findOption={(id, users) => users.find((u) => u.id === id)}
 *   onChange={(ids) => setSelectedUserIds(ids)}
 * />
 * ```
 */
export function ObjectAutocompleteField<TOption, TValue>({
  onChange,
  name,
  value,
  possibleValues,
  getOptionLabel,
  getOptionValue,
  findOption,
  focused,
}: ObjectAutocompleteFieldProps<TOption, TValue>) {
  const id = useMemo(() => createId(name), [name]);

  // Convert saved values back to options for display
  const selectedOptions = useMemo(() => {
    return value
      .map((v) => findOption(v, possibleValues))
      .filter((opt): opt is TOption => opt !== undefined);
  }, [value, possibleValues, findOption]);

  // Handle selection changes
  const handleChange = useCallback(
    (_: React.SyntheticEvent, newValue: TOption[]) => {
      const newValues = newValue.map((item) => getOptionValue(item));
      onChange(newValues);
    },
    [onChange, getOptionValue]
  );

  return (
    <div>
      <Autocomplete
        multiple
        options={possibleValues}
        value={selectedOptions}
        onChange={handleChange}
        getOptionLabel={getOptionLabel}
        isOptionEqualToValue={(option, val) =>
          getOptionValue(option) === getOptionValue(val)
        }
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
