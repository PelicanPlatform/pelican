import {NamespaceIcon} from "@/components";
import { Box, Typography } from '@mui/material';
import React from "react";
import {RegistryNamespace} from "@/index";

interface NamespaceTitleProps {
  namespace: RegistryNamespace;
}

const NamespaceTitle = ({namespace}: NamespaceTitleProps) => {
  return (
    <Box
      my={'auto'}
      ml={1}
      display={'flex'}
      flexDirection={'row'}
      alignItems={'center'}
      minWidth={0}
    >
      <NamespaceIcon serverType={namespace.type} />
      <Box>
        <Typography
          sx={{
            pt: '2px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          variant={"body1"}
        >
          {namespace.prefix}
        </Typography>
        <Typography
          sx={{
            mt: -.5,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            textTransform: 'capitalize',
            display: 'block',
          }}
          variant={'caption'}
        >
          {namespace.type}
        </Typography>
      </Box>
    </Box>
  )
}

export default NamespaceTitle;
