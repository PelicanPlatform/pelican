import { secureFetch } from '@/helpers/login';
import React, { useContext, useState } from 'react';
import { Box, Paper, Typography } from '@mui/material';
import { NamespaceIcon } from '@/components/Namespace/index';
import { NamespaceDropdown } from './NamespaceDropdown';
import { DirectorNamespace, ServerDetailed, ServerGeneral } from '@/types';
import { getDirectorServer } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';

export interface NamespaceCardProps {
  namespace: DirectorNamespace;
}

export const NamespaceCard = ({ namespace }: NamespaceCardProps) => {
  const dispatch = useContext(AlertDispatchContext);
  const [dropdownOpen, setDropdownOpen] = useState<boolean>(false);
  const [servers, setServers] = useState<ServerDetailed[] | undefined>(
    undefined
  );

  return (
    <>
      <Paper>
        <Box
          sx={{
            cursor: 'pointer',
            display: 'flex',
            width: '100%',
            justifyContent: 'space-between',
            border: 'solid #ececec 1px',
            borderRadius: '4px',
            transition: 'background-color 0.3s',
            p: 1,
          }}
          onClick={async () => {
            setDropdownOpen(!dropdownOpen);
            if (servers === undefined) {
              alertOnError(
                async () => setServers(await getAssociatedServers(namespace)),
                'Failed to fetch servers',
                dispatch
              );
            }
          }}
        >
          <Box my={'auto'} ml={1} display={'flex'} flexDirection={'row'}>
            <NamespaceIcon serverType={'namespace'} />
            <Typography sx={{ pt: '2px' }}>{namespace.path}</Typography>
          </Box>
        </Box>
      </Paper>
      <NamespaceDropdown
        namespace={namespace}
        servers={servers}
        transition={dropdownOpen}
      />
    </>
  );
};

const getAssociatedServers = async (namespace: DirectorNamespace) => {
  const servers = await Promise.all(
    [...namespace.origins, ...namespace.caches].map(async (name) =>
      (await getDirectorServer(name)).json()
    )
  );

  // Alert the console if any servers are undefined, as this is unlikely to happen naturally
  if (servers.some((s) => s === undefined)) {
    console.error('Failed to fetch all servers, some are undefined');
  }

  return servers.filter((s) => s !== undefined) as ServerDetailed[];
};

export default NamespaceCard;
