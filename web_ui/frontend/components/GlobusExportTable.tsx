/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import { getErrorMessage } from '@/helpers/util';
import {
  Box,
  Button,
  Paper,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { CheckCircle, InfoOutlined, Warning } from '@mui/icons-material';

import { ReactElement, useMemo } from 'react';
import useSWR from 'swr';
import { ValueLabel } from './DataExportTable';

interface GlobusExportEntry {
  uuid: string;
  displayName: string;
  federationPrefix: string;
  storagePrefix: string;
  status: 'Activated' | 'Inactive';
  description: undefined | string;
  httpsServer: string;
}

interface GlobusCollectionGroup {
  uuid: string;
  displayName: string;
  status: 'Activated' | 'Inactive';
  httpsServer: string;
  exports: { federationPrefix: string; storagePrefix: string }[];
}

const getGlobusExports = async (): Promise<GlobusExportEntry[]> => {
  let response = await fetch('/api/v1.0/origin_ui/globus/exports');
  if (response.ok) {
    const responseData = await response.json();
    return responseData;
  } else {
    throw new Error(await getErrorMessage(response));
  }
};

const activateBaseUrl = '/api/v1.0/origin_ui/globus/auth/login';

const GlobusCollectionCard = ({
  collection,
}: {
  collection: GlobusCollectionGroup;
}): ReactElement => {
  return (
    <Paper elevation={3} sx={{ mb: 2, p: 2, minWidth: 600 }}>
      <Box display={'flex'} alignItems={'flex-start'} justifyContent={'space-between'}>
        <Box flexGrow={1}>
          <ValueLabel label='Globus Collection Name' value={collection.displayName} />
          <ValueLabel label='Globus Collection UUID' value={collection.uuid} />
          <ValueLabel label='Https Server' value={collection.httpsServer} />
        </Box>
        <Box ml={4} mt={1}>
          {collection.status === 'Activated' ? (
            <Tooltip title="The collection is activated and it's ready to serve files">
              <Button color='success' startIcon={<CheckCircle />}>
                Activated
              </Button>
            </Tooltip>
          ) : (
            <Tooltip title='You need to activate the collection before Pelican can serve files from this collection'>
              <Button
                color={'warning'}
                variant='contained'
                startIcon={<Warning />}
                onClick={() => {
                  window.location.href = activateBaseUrl + '/' + collection.uuid;
                }}
              >
                Activate
              </Button>
            </Tooltip>
          )}
        </Box>
      </Box>

      <Box mt={2}>
        <Typography variant='subtitle2' color='text.secondary' gutterBottom>
          Exports
        </Typography>
        <Table size='small'>
          <TableHead>
            <TableRow>
              <TableCell>
                <Typography variant='caption' fontWeight='bold'>
                  Federation Prefix
                </Typography>
              </TableCell>
              <TableCell>
                <Box display='flex' alignItems='center' gap={0.5}>
                  <Typography variant='caption' fontWeight='bold'>
                    Storage Prefix
                  </Typography>
                  <Tooltip title='The path within the Globus Collection being exported.'>
                    <InfoOutlined sx={{ fontSize: 14, color: 'text.secondary', cursor: 'help' }} />
                  </Tooltip>
                </Box>
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {collection.exports.map((exp) => (
              <TableRow key={exp.federationPrefix}>
                <TableCell>
                  <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
                    {exp.federationPrefix}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
                    {exp.storagePrefix}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
    </Paper>
  );
};

export const GlobusExportTable = () => {
  const { data, error } = useSWR('getGlobusExport', getGlobusExports);

  const collections = useMemo<GlobusCollectionGroup[]>(() => {
    if (!data) return [];
    const map = new Map<string, GlobusCollectionGroup>();
    for (const entry of data) {
      if (!map.has(entry.uuid)) {
        map.set(entry.uuid, {
          uuid: entry.uuid,
          displayName: entry.displayName,
          status: entry.status,
          httpsServer: entry.httpsServer,
          exports: [],
        });
      }
      map.get(entry.uuid)!.exports.push({
        federationPrefix: entry.federationPrefix,
        storagePrefix: entry.storagePrefix,
      });
    }
    return Array.from(map.values());
  }, [data]);

  if (error) {
    return (
      <Box p={1}>
        <Typography sx={{ color: 'red' }} variant={'subtitle2'}>
          {error.toString()}
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      {data ? (
        collections.map((collection) => (
          <GlobusCollectionCard collection={collection} key={collection.uuid} />
        ))
      ) : (
        <Skeleton variant={'rectangular'} height={200} width={'100%'} />
      )}
    </Box>
  );
};
