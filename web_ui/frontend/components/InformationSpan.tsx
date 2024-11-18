import { Box, Tooltip, Typography } from '@mui/material';
import { grey } from '@mui/material/colors';
import React, { ReactNode } from 'react';

export const InformationSpanHeader = ({
  title,
  indent = 0
}: {
  title: string,
  indent?: number
}) => {
  return (
    <Box
      sx={{
        '&:nth-of-type(odd)': {
          bgcolor: grey[300],
          p: '4px 6px',
          borderRadius: '4px',
        },
        '&:nth-of-type(even)': {
          p: '4px 6px',
        },
        display: 'flex',
        justifyContent: 'space-between',
      }}
    >
      <Typography variant={'body2'} sx={{ display: 'inline', mr: 2 }}>
        {"\u00A0\u00A0\u00A0\u00A0".repeat(Math.max(indent - 1, 0))}{indent > 0 ? "↳\u00A0" : ""}{title}
      </Typography>
      <Typography variant={'body2'} sx={{ display: 'inline' }}>
      </Typography>
    </Box>
  );
}

export const InformationSpan = ({
  name,
  value,
  indent = 0
}: {
  name: string;
  value: string;
  indent?: number;
}) => {
  return (
    <Tooltip title={name} placement={'right'}>
      <Box
        sx={{
          '&:nth-of-type(odd)': {
            bgcolor: grey[300],
            p: '4px 6px',
            borderRadius: '4px',
          },
          '&:nth-of-type(even)': {
            p: '4px 6px',
          },
          display: 'flex',
        }}
      >
        <Typography variant={'body2'} sx={{ display: 'inline', mr: 2 }}>
          {"\u00A0\u00A0\u00A0\u00A0".repeat(Math.max(indent - 1, 0))}{indent > 0 ? "↳\u00A0" : ""}{name}:
        </Typography>
        <Typography variant={'body2'} sx={{ display: 'inline' }}>
          {value}
        </Typography>
      </Box>
    </Tooltip>
  );
};

export default InformationSpan;
