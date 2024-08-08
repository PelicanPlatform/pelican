import { LinearProgress, TextField, Box } from '@mui/material';
import React from 'react';

interface LoadingFieldProps {
  name: string;
}

export const LoadingField = ({ name }: LoadingFieldProps) => {
  return (
    <>
      <TextField
        fullWidth
        size='small'
        label={name}
        variant={'outlined'}
        disabled={true}
        value={''}
      />
      <Box
        sx={{
          mt: '-4px',
          borderRadius: '2px',
          overflow: 'hidden',
        }}
      >
        <LinearProgress />
      </Box>
    </>
  );
};
