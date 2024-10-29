import React, { useContext, useMemo, useRef, useState } from 'react';
import { Authenticated, secureFetch } from '@/helpers/login';
import { Avatar, Box, IconButton, Tooltip, Typography } from '@mui/material';
import { Block, Check, Edit, Person } from '@mui/icons-material';
import Link from 'next/link';

import { Alert, Namespace } from '@/index';
import InformationDropdown from './InformationDropdown';
import { getServerType, NamespaceIcon } from '@/components/Namespace/index';
import { User } from '@/index';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { approveNamespace, denyNamespace } from '@/helpers/api';

export interface PendingCardProps {
  namespace: Namespace;
  onUpdate: () => void;
  onAlert: (alert: Alert) => void;
  authenticated?: User;
}

export const PendingCard = ({
  namespace,
  onUpdate,
  onAlert,
  authenticated,
}: PendingCardProps) => {
  const ref = useRef<HTMLDivElement>(null);
  const [transition, setTransition] = useState<boolean>(false);

  const dispatch = useContext(AlertDispatchContext);

  return (
    <Box>
      <Box
        sx={{
          cursor: 'pointer',
          display: 'flex',
          width: '100%',
          justifyContent: 'space-between',
          border: 'solid #ececec 1px',
          borderRadius: transition ? '10px 10px 0px 0px' : 2,
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
        <Box display={'flex'}>
          <Box my={'auto'} display={'flex'} flexDirection={'row'}>
            {authenticated !== undefined &&
              authenticated.user == namespace.admin_metadata.user_id && (
                <Box sx={{ borderRight: 'solid 1px #ececec', mr: 1 }}>
                  <Tooltip title={'Created By You'}>
                    <Avatar
                      sx={{ height: '40px', width: '40px', my: 'auto', mr: 2 }}
                    >
                      <Person />
                    </Avatar>
                  </Tooltip>
                </Box>
              )}
            {authenticated?.role == 'admin' && (
              <>
                <Tooltip title={'Deny Registration'}>
                  <IconButton
                    sx={{ bgcolor: '#ff00001a', mx: 1 }}
                    color={'error'}
                    onClick={async (e) => {
                      e.stopPropagation();
                      await alertOnError(
                        () => denyNamespace(namespace.id),
                        "Couldn't deny namespace",
                        dispatch
                      );
                      onUpdate();
                    }}
                  >
                    <Block />
                  </IconButton>
                </Tooltip>
                <Tooltip title={'Approve Registration'}>
                  <IconButton
                    sx={{ bgcolor: '#2e7d3224', mx: 1 }}
                    color={'success'}
                    onClick={async (e) => {
                      e.stopPropagation();
                      await alertOnError(
                        () => approveNamespace(namespace.id),
                        "Couldn't approve namespace",
                        dispatch
                      );
                      onUpdate();
                    }}
                  >
                    <Check />
                  </IconButton>
                </Tooltip>
              </>
            )}
            {(authenticated?.role == 'admin' ||
              authenticated?.user == namespace.admin_metadata.user_id) && (
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
    </Box>
  );
};

export default PendingCard;
