import { Authenticated, secureFetch } from '@/helpers/login';
import React, { useContext, useEffect, useRef, useState } from 'react';
import {
  Avatar,
  Box,
  IconButton,
  Paper,
  Tooltip,
  Typography,
  Switch,
  Snackbar,
  FormGroup,
  FormControlLabel,
  Portal,
  Alert,
} from '@mui/material';
import { red, grey } from '@mui/material/colors';
import { Server } from '@/index';
import { Equalizer, Language } from '@mui/icons-material';
import { NamespaceIcon } from '@/components/Namespace/index';
import useSWR from 'swr';
import Link from 'next/link';
import { User } from '@/index';
import { alertOnError, getErrorMessage } from '@/helpers/util';
import { DirectorDropdown } from '@/app/director/components/DirectorDropdown';
import { ServerDetailed, ServerGeneral } from '@/types';
import { allowServer, filterServer, getDirectorServer } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';

export interface DirectorCardProps {
  server: ServerGeneral;
  authenticated?: User;
}

export const DirectorCard = ({ server, authenticated }: DirectorCardProps) => {
  const [disabled, setDisabled] = useState<boolean>(false);
  const [dropdownOpen, setDropdownOpen] = useState<boolean>(false);
  const [detailedServer, setDetailedServer] = useState<
    ServerDetailed | undefined
  >();

  const dispatch = useContext(AlertDispatchContext);

  const { mutate } = useSWR<Server[]>('getServers');

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
            '&:hover': {
              bgcolor: server.healthStatus === 'Error' ? red[200] : grey[200],
            },
            bgcolor:
              server.healthStatus === 'Error' ? red[100] : 'secondary.main',
            p: 1,
          }}
          onClick={async () => {
            setDropdownOpen(!dropdownOpen);
            if (detailedServer === undefined) {
              alertOnError(
                async () => {
                  const response = await getDirectorServer(server.name);
                  setDetailedServer(await response.json());
                },
                'Failed to fetch server details',
                dispatch
              );
            }
          }}
        >
          <Box my={'auto'} ml={1} display={'flex'} flexDirection={'row'}>
            <NamespaceIcon
              serverType={server.type.toLowerCase() as 'cache' | 'origin'}
            />
            <Typography sx={{ pt: '2px' }}>
              {server.name}
              {server?.version && <> &#x2022; {server.version}</>}
            </Typography>
          </Box>
          <Box display={'flex'} flexDirection={'row'}>
            <Box my={'auto'} display={'flex'}>
              {authenticated && authenticated.role == 'admin' && (
                <Tooltip title={'Toggle Server Downtime'}>
                  <FormGroup>
                    <FormControlLabel
                      labelPlacement='start'
                      control={
                        <Switch
                          key={server.name}
                          disabled={disabled}
                          checked={!server.filtered}
                          color={'success'}
                          onClick={async (e) => {
                            e.stopPropagation();

                            // Disable the switch
                            setDisabled(true);

                            // Update the server
                            await alertOnError(
                              async () => {
                                if (server.filtered) {
                                  await allowServer(server.name);
                                } else {
                                  await filterServer(server.name);
                                }
                              },
                              'Failed to toggle server status',
                              dispatch
                            );

                            mutate();

                            setDisabled(false);
                          }}
                        />
                      }
                      label={server.filtered ? 'Disabled' : 'Active'}
                    />
                  </FormGroup>
                </Tooltip>
              )}
              {server?.webUrl && (
                <Box ml={1}>
                  <Link href={server.webUrl} target={'_blank'}>
                    <Tooltip title={'View Server Website'}>
                      <IconButton size={'small'}>
                        <Language />
                      </IconButton>
                    </Tooltip>
                  </Link>
                </Box>
              )}
              {authenticated &&
                authenticated.role == 'admin' &&
                server?.webUrl && (
                  <Box ml={1}>
                    <Link
                      href={`/director/metrics/${server.type.toLowerCase()}/?server_name=${server.name}`}
                      target={'_blank'}
                    >
                      <Tooltip title={'View Server Metrics'}>
                        <IconButton size={'small'}>
                          <Equalizer />
                        </IconButton>
                      </Tooltip>
                    </Link>
                  </Box>
                )}
            </Box>
          </Box>
        </Box>
      </Paper>
      <DirectorDropdown
        server={detailedServer || server}
        transition={dropdownOpen}
      />
    </>
  );
};

export default DirectorCard;
