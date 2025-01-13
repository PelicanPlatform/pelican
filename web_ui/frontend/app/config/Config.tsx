/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

import {
  Box,
  Grid,
  Typography,
  Snackbar,
  Button,
  IconButton,
  Alert,
} from '@mui/material';
import React, {
  memo,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  AppRegistration,
  AssistantDirection,
  TripOrigin,
  Cached,
  Download,
} from '@mui/icons-material';
import useSWR from 'swr';
import { merge, isMatch, isEqual } from 'lodash';
import * as yaml from 'js-yaml';
import { Main } from '@/components/layout/Main';
import { submitConfigChange } from '@/components/configuration/util';
import {
  ParameterMetadataList,
  ParameterMetadataRecord,
  ParameterValueRecord,
} from '@/components/configuration';
import { stripNulls, flattenObject } from './util';
import StatusSnackBar, {
  StatusSnackBarProps,
} from '@/components/StatusSnackBar';
import { ServerType } from '@/index';
import { alertOnError, getEnabledServers } from '@/helpers/util';
import DownloadButton from '@/components/DownloadButton';
import { PaddedContent } from '@/components/layout';
import { ConfigDisplay, TableOfContents, RestartBox } from '@/app/config/components';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { getConfig } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';

function Config({ metadata }: { metadata: ParameterMetadataRecord }) {
  const dispatch = useContext(AlertDispatchContext);

  const [status, setStatus] = useState<StatusSnackBarProps | undefined>(
    undefined
  );
  const [patch, _setPatch] = useState<ParameterValueRecord>({});

  const { data, mutate, error } = useSWR<ParameterValueRecord | undefined>(
    'getConfig',
    async () =>
      await alertOnError(getConfigJson, 'Could not get config', dispatch)
  );

  const serverConfig = useMemo(() => {
    return flattenObject(data || {});
  }, [data]);

  const setPatch = useCallback(
    (fieldPatch: any) => {
      _setPatch((p: any) => {
        return { ...p, ...fieldPatch };
      });
    },
    [_setPatch]
  );

  const updatesPending = useMemo(() => {
    return !Object.keys(patch).every((key) =>
      isEqual(patch[key], serverConfig?.[key])
    );
  }, [serverConfig, patch]);

  return (
    <AuthenticatedContent redirect={true} trustThenValidate={true}>
      <Box display={'flex'} flexDirection={'row'}>
        <Typography variant={'h4'} component={'h2'} mb={1}>
          Configuration
          {serverConfig && (
            <Box ml={2} display={'inline'}>
              <DownloadButton
                Button={IconButton}
                mimeType={'text/yaml'}
                data={yaml.dump(stripNulls(structuredClone(data)))}
              >
                <Download />
              </DownloadButton>
            </Box>
          )}
        </Typography>
      </Box>
      <Grid container>
        <Grid item>
          <RestartBox />
        </Grid>
      </Grid>
      <Grid container spacing={2} sx={{ mt: -5 }}>
        <Grid item xs={12} md={8} lg={6}>
          <Box>
            {error && (
              <Alert severity={'warning'}>{(error as Error).message}</Alert>
            )}
          </Box>
          <ConfigDisplay
            config={serverConfig}
            patch={patch}
            metadata={metadata}
            onChange={setPatch}
          />
          <Snackbar
            anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
            open={updatesPending}
            message='Save Changes'
            action={
              <Box>
                <Button
                  onClick={async () => {
                    try {
                      await submitConfigChange(patch);
                      setStatus({
                        message: 'Changes Saved, Restarting Server',
                      });

                      // Refresh the page after 3 seconds
                      setTimeout(() => {
                        mutate();
                        setStatus(undefined);
                        _setPatch({});
                      }, 3000);
                    } catch (e) {
                      setStatus({
                        severity: 'error',
                        message: (e as string).toString(),
                      });
                    }
                  }}
                >
                  Save
                </Button>
                <Button
                  onClick={() => {
                    _setPatch({});
                  }}
                >
                  Clear
                </Button>
              </Box>
            }
          />
          {status && <StatusSnackBar key={status.message} {...status} />}
        </Grid>
        <Grid item xs={12} md={4} lg={3} display={{ xs: 'none', md: 'block' }}>
          <Box pt={2}>
            <TableOfContents metadata={metadata} />
          </Box>
        </Grid>
      </Grid>
    </AuthenticatedContent>
  );
}

const getConfigJson = async (): Promise<ParameterValueRecord | undefined> => {
  const response = await getConfig();
  if (response) {
    return await response.json();
  }
};

export default Config;
