import { TextField, StandardTextFieldProps } from '@mui/material';
import React from 'react';

export interface CodeInputFieldProps extends StandardTextFieldProps {
  name: string;
  label: string;
  validator?: (value: string) => string | undefined;
}

const CodeInputField = ({
  name,
  label,
  validator,
  ...props
}: CodeInputFieldProps) => {
  const [error, setError] = React.useState<string | undefined>(undefined);

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;

    // If validator is provided, use it to validate the input
    if (validator) {
      const error = validator(value);
      setError(error);
    }
  };

  return (
    <TextField
      {...props}
      required
      fullWidth
      size={'small'}
      id={name}
      name={name}
      label={label}
      variant={'outlined'}
      multiline={true}
      inputProps={{
        style: {
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          lineHeight: '0.9rem',
          minHeight: '1.5rem',
          paddingTop: '0.6rem',
        },
      }}
      error={error !== undefined}
      helperText={error}
      onChange={handleChange}
    />
  );
};

export default CodeInputField;
