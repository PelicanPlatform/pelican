import { secureFetch } from '@/helpers/login';
import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
} from '@mui/material';
import { NamespaceIcon } from '@/components/Namespace/index';
import { NamespaceDropdown } from './NamespaceDropdown';
import { Namespace, ServerDetailed, ServerGeneral } from '@/types';

export interface NamespaceCardProps {
  namespace: Namespace;
}

export const NamespaceCard = ({ namespace }: NamespaceCardProps) => {
  const [dropdownOpen, setDropdownOpen] = useState<boolean>(false);
  const [servers, setServers] = useState<ServerDetailed[] | undefined>(undefined);

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
              setServers(await getAssociatedServers(namespace));
            }
          }}
        >
          <Box my={'auto'} ml={1} display={'flex'} flexDirection={'row'}>
            <NamespaceIcon
              serverType={'namespace'}
            />
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

const getAssociatedServers = async (namespace: Namespace) => {
  const servers = await Promise.all([...namespace.origins, ...namespace.caches].map(getServer));

  // Alert the console if any servers are undefined, as this is unlikely to happen naturally
  if(servers.some((s) => s === undefined)) {
    console.error("Failed to fetch all servers, some are undefined");
  }

  return servers.filter((s) => s !== undefined) as ServerDetailed[];

}

// TODO: Consolidate this when https://github.com/PelicanPlatform/pelican/pull/1687 is merged
const getServer = async (name: string): Promise<ServerDetailed | undefined> => {
  try {
    const response = await secureFetch(`/api/v1.0/director_ui/servers/${name}`);
    if (response.ok) {
      return await response.json();
    } else {
      return undefined;
    }
  } catch (e) {
    return undefined;
  }
};

export default NamespaceCard;
