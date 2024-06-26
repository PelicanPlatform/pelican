import { Box, IconButton, Tooltip, Typography } from '@mui/material';
import Link from 'next/link';
import React from 'react';
import { Add } from '@mui/icons-material';

export const CreateNamespaceCard = ({
  text,
  url,
}: {
  text: string;
  url: string;
}) => {
  return (
    <Box>
      <Box
        sx={{
          display: 'flex',
          width: '100%',
          justifyContent: 'space-between',
          border: 'solid #ececec 1px',
          borderRadius: 2,
          p: 1,
        }}
        bgcolor={'secondary'}
      >
        <Box my={'auto'} ml={1}>
          <Typography>{text ? text : 'Register Namespace'}</Typography>
        </Box>
        <Box>
          <Tooltip title={'Register Namespace'}>
            <Link href={url}>
              <IconButton
                sx={{ bgcolor: '#2e7d3224' }}
                onClick={(e: React.MouseEvent) => e.stopPropagation()}
              >
                <Add />
              </IconButton>
            </Link>
          </Tooltip>
        </Box>
      </Box>
    </Box>
  );
};

export default CreateNamespaceCard;
