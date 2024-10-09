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
} from '@mui/material';
import React, { memo, useCallback, useEffect, useMemo, useState } from 'react';
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
import { ButtonLink, Sidebar } from '@/components/layout/Sidebar';
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
import { getEnabledServers } from '@/helpers/util';
import DownloadButton from '@/components/DownloadButton';
import { PaddedContent } from '@/components/layout';
import { ConfigDisplay, TableOfContents } from '@/app/config/components';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

function Config({ metadata }: { metadata: ParameterMetadataRecord }) {
  const [status, setStatus] = useState<StatusSnackBarProps | undefined>(
    undefined
  );
  const [patch, _setPatch] = useState<ParameterValueRecord>({});

  const {
    data,
    mutate,
    error,
  } = useSWR<ParameterValueRecord>('getConfig', getConfig);
  const { data: enabledServers } = useSWR<ServerType[]>(
    'getEnabledServers',
    getEnabledServers,
    {
      fallbackData: ['origin', 'registry', 'director', 'cache'],
    }
  );

  const serverConfig = useMemo(() => {
    return flattenObject(data || {});
  }, [data])

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
    <>
      <Sidebar>
        {enabledServers && enabledServers.includes('origin') && (
          <ButtonLink title={'Origin'} href={'/origin/'}>
            <TripOrigin />
          </ButtonLink>
        )}
        {enabledServers && enabledServers.includes('director') && (
          <ButtonLink title={'Director'} href={'/director/'}>
            <AssistantDirection />
          </ButtonLink>
        )}
        {enabledServers && enabledServers.includes('registry') && (
          <ButtonLink title={'Registry'} href={'/registry/'}>
            <AppRegistration />
          </ButtonLink>
        )}
        {enabledServers && enabledServers.includes('cache') && (
          <ButtonLink title={'Cache'} href={'/cache/'}>
            <Cached />
          </ButtonLink>
        )}
      </Sidebar>
      <Main>
        <PaddedContent>
          <AuthenticatedContent redirect={true}>
            <Box display={'flex'} flexDirection={'row'}>
              <Typography variant={'h4'} component={'h2'} mb={1}>
                Configuration
                {serverConfig && (
                  <Box ml={2} display={'inline'}>
                    <DownloadButton
                      Button={IconButton}
                      mimeType={'text/yaml'}
                      data={yaml.dump(
                        stripNulls(structuredClone(data))
                      )}
                    >
                      <Download />
                    </DownloadButton>
                  </Box>
                )}
              </Typography>
            </Box>
            <Grid container spacing={2}>
              <Grid item xs={12} md={8} lg={6}>
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
              <Grid
                item
                xs={12}
                md={4}
                lg={3}
                display={{ xs: 'none', md: 'block' }}
              >
                <Box pt={2}>
                  <TableOfContents metadata={metadata} />
                </Box>
              </Grid>
            </Grid>
          </AuthenticatedContent>
        </PaddedContent>
      </Main>
    </>
  );
}

const getConfig = async (): Promise<ParameterValueRecord> => {
  let response = await fetch('/api/v1.0/config');
  let data = await response.json();
  return data;
}

export default Config;
