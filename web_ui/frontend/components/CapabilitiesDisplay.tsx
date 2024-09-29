import { Capabilities } from '@/index';
import { Box, Tooltip, Typography } from '@mui/material';
import { grey } from '@mui/material/colors';
import { Check, Clear } from '@mui/icons-material';
import React from 'react';

export const CapabilitiesDisplay = ({
  capabilities,
}: {
  capabilities: Capabilities;
}) => {
  return (
    <>
      {Object.entries(capabilities).map(([key, value]) => {
        return (
          <Tooltip title={key} key={key}>
            <CapabilitiesChip key={key} name={key} value={value} />
          </Tooltip>
        );
      })}
    </>
  );
};

export const CapabilitiesChip = ({
  name,
  value,
}: {
  name: string;
  value: boolean;
}) => {
  return (
    <Box
      sx={{
        borderRadius: 1,
        display: 'flex',
        justifyContent: 'space-between',
        py: 0.4,
        px: 1,
        mb: 0.2,
        backgroundColor: value ? grey[300] : grey[100],
        color: value ? 'black' : grey[700],
        border: '1px 1px solid black',
      }}
    >
      <Typography variant={'body2'}>{name}</Typography>
      <Box display={'flex'}>
        {value ? <Check fontSize='small' /> : <Clear fontSize='small' />}
      </Box>
    </Box>
  );
};
