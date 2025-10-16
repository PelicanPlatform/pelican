'use client';

import { Box, BoxProps } from '@mui/material';

const ListCard = ({ children, sx, ...props }: BoxProps) => {
  return (
    <Box
      {...props}
      sx={{
        ...sx,
        width: '100%',
        display: 'flex',
        flexDirection: 'row',
        justifyContent: 'space-between',
        border: 'solid #ececec 1px',
        borderRadius: 2,
        p: 1,
      }}
    >
      {children}
    </Box>
  );
};

export default ListCard;
