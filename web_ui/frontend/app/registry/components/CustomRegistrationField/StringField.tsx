import { TextField } from '@mui/material';
import type { StandardTextFieldProps } from '@mui/material';
import React from 'react';

import type { CustomRegistrationFieldProps } from './index.d';

type TextFieldProps = Omit<StandardTextFieldProps, 'onChange'> &
  CustomRegistrationFieldProps<string>;

interface StringFieldProps extends TextFieldProps {
  validator?: (value: string) => string | undefined;
}

const StringField = ({
  onChange,
  displayed_name,
  name,
  required,
  description,
  value,
  validator,
  ...props
}: StringFieldProps) => {
  const [error, setError] = React.useState<string | undefined>(undefined);

  // Check that the value is a number or undefined throwing error if not
  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    const error = validator ? validator(value) : undefined;

    if (error) {
      setError(error);
    } else {
      setError(undefined);
    }

    onChange(value === '' ? null : value);
  };

  return (
    <TextField
      {...props}
      fullWidth
      required={required}
      size='small'
      variant={'outlined'}
      label={displayed_name}
      name={name}
      value={value || ''}
      error={error !== undefined}
      helperText={error || description}
      onChange={handleChange}
    />
  );
};

export default StringField;
export { StringField };
