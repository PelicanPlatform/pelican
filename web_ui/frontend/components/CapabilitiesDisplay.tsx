import { Capabilities } from '@/types';
import { Box, Tooltip, Typography } from '@mui/material';
import { green, grey } from '@mui/material/colors';
import { Check, Clear } from '@mui/icons-material';
import React, { useMemo } from 'react';

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
            <CapabilitiesChip key={key} name={key} value={value as boolean} />
          </Tooltip>
        );
      })}
    </>
  );
};

/**
 * Capabilities chip used to convey the capabilities of a server or namespace
 * There are two levels of activity to help represent the relationship between
 * activity and the server or namespace.
 * @param name
 * @param value
 * @param active
 * @constructor
 */
export const CapabilitiesChip = ({
  name,
  value,
  parentValue,
}: {
  name: string;
  value: boolean;
  parentValue?: boolean;
}) => {
  // Switch statement to determine the color of the chip
  const isActive = useMemo(() => {
    return parentValue !== undefined ? value && parentValue : value;
  }, [value, parentValue]);

  return (
    <Box
      sx={{
        borderRadius: 1,
        display: 'flex',
        justifyContent: 'space-between',
        py: 0.4,
        px: 1,
        mb: 0.2,
        backgroundColor: isActive ? green[300] : grey[100],
        color: isActive ? 'black' : grey[700],
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
