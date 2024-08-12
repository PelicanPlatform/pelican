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
  Skeleton,
  Snackbar,
  Button,
  IconButton,
} from '@mui/material';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AppRegistration,
  AssistantDirection,
  TripOrigin,
  Cached,
  Download,
} from '@mui/icons-material';
import useSWR from 'swr';
import { merge, isMatch } from 'lodash';
import * as yaml from 'js-yaml';
import { ButtonLink, Sidebar } from '@/components/layout/Sidebar';
import { Main } from '@/components/layout/Main';
import { submitConfigChange } from '@/components/Config/util';
import {
  ParameterInputProps,
  Config,
  ConfigMetadata,
} from '@/components/Config/index';
import {
  deleteKey,
  getConfigMetadata,
  stripNulls,
  stripTypes,
  updateValue,
} from './util';
import StatusSnackBar, {
  StatusSnackBarProps,
} from '@/components/StatusSnackBar';
import { useRouter } from 'next/navigation';
import { AppRouterInstance } from 'next/dist/shared/lib/app-router-context.shared-runtime';
import { ServerType } from '@/index';
import { getEnabledServers } from '@/helpers/util';
import DownloadButton from '@/components/DownloadButton';
import { PaddedContent } from '@/components/layout';
import { ConfigDisplay, TableOfContents } from '@/app/config/components';

function Config() {
  const router = useRouter();

  const [status, setStatus] = useState<StatusSnackBarProps | undefined>(
    undefined
  );
  const [config, setConfig] = useState<Config | undefined>(undefined);
  const [configKey, setConfigKey] = useState<number>(0);
  const [patch, _setPatch] = useState<any>({});

  const { data: enabledServers } = useSWR<ServerType[]>(
    'getEnabledServers',
    getEnabledServers,
    {
      fallbackData: ['origin', 'registry', 'director', 'cache'],
    }
  );
  const { data: configMetadata } = useSWR<ConfigMetadata | undefined>(
    'getConfigMetadata',
    getConfigMetadata
  );

  const setPatch = useCallback(
    (fieldPatch: any) => {
      _setPatch((p: any) => structuredClone(merge(p, fieldPatch)));
    },
    [_setPatch]
  );

  const _getConfig = useCallback(
    () => getConfig(setConfig, setConfigKey, setStatus, router),
    [setConfig, setConfigKey, setStatus, router]
  );

  useEffect(() => {
    _getConfig();
  }, []);

  const filteredConfig = useMemo(() => {
    return filterConfig(config, configMetadata, enabledServers);
  }, [config, enabledServers, configMetadata]);

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
          <Box display={'flex'} flexDirection={'row'}>
            <Typography variant={'h4'} component={'h2'} mb={1}>
              Configuration
            </Typography>
            {config && (
              <Box ml={2}>
                <DownloadButton
                  Button={IconButton}
                  mimeType={'text/yaml'}
                  data={yaml.dump(
                    stripNulls(stripTypes(structuredClone(config)))
                  )}
                >
                  <Download />
                </DownloadButton>
              </Box>
            )}
          </Box>
          <Grid container spacing={2}>
            <Grid item xs={12} md={8} lg={6}>
              <form>
                {filteredConfig === undefined ||
                configMetadata === undefined ? (
                  <Box borderRadius={1} overflow={'hidden'}>
                    <Skeleton
                      variant='rectangular'
                      animation='wave'
                      height={'90vh'}
                    />
                  </Box>
                ) : (
                  <ConfigDisplay
                    key={configKey.toString()}
                    id={[]}
                    name={''}
                    value={filteredConfig}
                    level={4}
                    onChange={setPatch}
                  />
                )}
              </form>
              <Snackbar
                anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
                open={!isMatch(config === undefined ? {} : config, patch)}
                message='Save Changes'
                action={
                  <Box>
                    <Button
                      onClick={async () => {
                        try {
                          await submitConfigChange(patch);
                          _setPatch({});
                          setStatus({
                            message: 'Changes Saved, Restarting Server',
                          });
                          setTimeout(_getConfig, 3000);
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
                        _getConfig();
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
              {filteredConfig === undefined ? (
                <Box borderRadius={1} overflow={'hidden'}>
                  <Skeleton
                    variant='rectangular'
                    animation='wave'
                    height={'500px'}
                  />
                </Box>
              ) : (
                <Box pt={2}>
                  <TableOfContents
                    id={[]}
                    name={''}
                    value={filteredConfig}
                    level={1}
                  />
                </Box>
              )}
            </Grid>
          </Grid>
        </PaddedContent>
      </Main>
    </>
  );
}

const filterConfig = (
  config?: Config,
  configMetadata?: ConfigMetadata,
  enabledServers?: ServerType[]
) => {
  if (!config) {
    return undefined;
  }

  if (!enabledServers || !configMetadata) {
    return config;
  }

  // Filter out the inactive config values
  const filteredConfig: Config = structuredClone(config);
  Object.entries(configMetadata).forEach(([key, value]) => {
    if (
      [...enabledServers, '*'].filter((i) => value.components.includes(i))
        .length === 0
    ) {
      deleteKey(filteredConfig, key.split('.'));
    } else {
      updateValue(filteredConfig, key.split('.'), configMetadata[key]);
    }
  });

  // Filter out read-only values
  deleteKey(filteredConfig, ['ConfigDir']);

  return filteredConfig;
};

const getConfig = async (
  setConfig: (c?: Config) => void,
  setConfigKey: (f: (k: number) => number) => void,
  setStatus: (s?: StatusSnackBarProps) => void,
  router: AppRouterInstance
) => {
  let response = await fetch('/api/v1.0/config');
  if (response.ok) {
    const data = await response.json();
    setConfig(data);
    setStatus(undefined);
    setConfigKey((k) => k + 1);
  } else {
    setConfig(undefined);
    if (response.status === 401) {
      setStatus({
        severity: 'error',
        message: 'Unauthorized',
        action: {
          label: 'Login',
          onClick: () => router.push('/login/?returnURL=/view/config/'),
        },
      });
    } else {
      setTimeout(
        () => getConfig(setConfig, setConfigKey, setStatus, router),
        2000
      );
    }
  }
};

export default Config;
