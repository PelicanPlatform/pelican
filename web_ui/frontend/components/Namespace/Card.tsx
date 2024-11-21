import { Alert, Alert as AlertType, Namespace } from '@/index';
import React, { useContext, useRef, useState } from 'react';
import {
  Avatar,
  Box,
  IconButton,
  Paper,
  Tooltip,
  Typography,
} from '@mui/material';
import { Delete, Download, Edit, Person } from '@mui/icons-material';
import Link from 'next/link';

import InformationDropdown from './InformationDropdown';
import { NamespaceIcon } from '@/components/Namespace/index';
import { User } from '@/index';
import { deleteNamespace } from '@/helpers/api';
import { useSWRConfig } from 'swr';
import { AlertDispatchContext } from '@/components/AlertProvider';
import CodeBlock from '@/components/CodeBlock';
import { alertOnError } from '@/helpers/util';

export interface CardProps {
  namespace: Namespace;
  onUpdate?: () => void;
  authenticated?: User;
}

export const Card = ({ namespace, authenticated, onUpdate }: CardProps) => {
  const dispatch = useContext(AlertDispatchContext);
  const ref = useRef<HTMLDivElement>(null);
  const [transition, setTransition] = useState<boolean>(false);
  const { mutate } = useSWRConfig();
  return (
    <>
      <Paper elevation={transition ? 2 : 0}>
        <Box
          sx={{
            cursor: 'pointer',
            display: 'flex',
            width: '100%',
            justifyContent: 'space-between',
            border: 'solid #ececec 1px',
            borderRadius: '4px',
            '&:hover': {
              bgcolor: '#ececec',
            },
            p: 1,
          }}
          bgcolor={'secondary'}
          onClick={() => setTransition(!transition)}
        >
          <Box my={'auto'} ml={1} display={'flex'} flexDirection={'row'}>
            <NamespaceIcon serverType={namespace.type} />
            <Typography sx={{ pt: '2px' }}>{namespace.prefix}</Typography>
          </Box>
          <Box display={'flex'} flexDirection={'row'}>
            <Box my={'auto'} display={'flex'}>
              {authenticated !== undefined &&
                authenticated.user == namespace.admin_metadata.user_id && (
                  <Box sx={{ borderRight: 'solid 1px #ececec', mr: 1 }}>
                    <Tooltip title={'Created By You'}>
                      <Avatar
                        sx={{
                          height: '40px',
                          width: '40px',
                          my: 'auto',
                          mr: 2,
                        }}
                      >
                        <Person />
                      </Avatar>
                    </Tooltip>
                  </Box>
                )}
              <Tooltip title={'Download Public Key'}>
                <a
                  href={`/api/v1.0/registry_ui/namespaces/${namespace.id}/pubkey`}
                >
                  <IconButton
                    onClick={(e: React.MouseEvent) => e.stopPropagation()}
                    sx={{ mx: 1 }}
                  >
                    <Download />
                  </IconButton>
                </a>
              </Tooltip>
              {authenticated?.role == 'admin' && (
                <>
                  <Tooltip title={'Edit Registration'}>
                    <Link
                      href={`/registry/${namespace.type}/edit/?id=${namespace.id}`}
                    >
                      <IconButton
                        onClick={(e: React.MouseEvent) => e.stopPropagation()}
                      >
                        <Edit />
                      </IconButton>
                    </Link>
                  </Tooltip>
                  <Tooltip title={'Delete Registration'}>
                    <IconButton
                      sx={{ bgcolor: '#ff00001a', mx: 1 }}
                      color={'error'}
                      onClick={async (e) => {
                        e.stopPropagation();
                        await alertOnError(
                          async () => await deleteNamespace(namespace.id),
                          'Could Not Delete Registration',
                          dispatch
                        );
                        setTimeout(() => mutate('getNamespaces'), 600);
                        if (onUpdate) {
                          onUpdate();
                        }
                      }}
                    >
                      <Delete />
                    </IconButton>
                  </Tooltip>
                </>
              )}
            </Box>
          </Box>
        </Box>
        <Box ref={ref}>
          <InformationDropdown
            adminMetadata={namespace.admin_metadata}
            transition={transition}
            parentRef={ref}
          />
        </Box>
      </Paper>
    </>
  );
};

export default Card;
