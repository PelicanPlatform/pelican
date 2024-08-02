import { TextField } from '@mui/material';
import React from 'react';

interface ErrorFieldProps {
  label: string;
  error: string;
}

const ErrorField = ({ label, error }: ErrorFieldProps) => {
  return (
    <TextField
      fullWidth
      size='small'
      variant={'outlined'}
      label={label}
      disabled={true}
      helperText={error}
      error={true}
    />
  );
};

export default ErrorField;
export { ErrorField };
