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

import { Box, Grid, Skeleton, Typography } from '@mui/material';
import { useContext, useMemo } from 'react';
import useSWR from 'swr';
import { DirectorCardList } from './components';
import { getUser } from '@/helpers/login';
import FederationOverview from '@/components/FederationOverview';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { PaddedContent } from '@/components/layout';
import { DirectorNamespace, ServerGeneral } from '@/types';
import { NamespaceCardList } from './components/NamespaceCardList';
import { getDirectorServers, getDirectorNamespaces } from '@/helpers/get';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';

export default function Page() {
  const dispatch = useContext(AlertDispatchContext);

  const { data } = useSWR<ServerGeneral[] | undefined>(
    'getDirectorServers',
    async () =>
      await alertOnError(getDirectorServers, 'Failed to fetch servers', dispatch)
  );

  const { data: namespaces } = useSWR<DirectorNamespace[] | undefined>(
    'getDirectorNamespaces',
    async () => await alertOnError(getDirectorNamespaces, "Faild to fetch Namespaces", dispatch)
  );

  const { data: user, error } = useSWR('getUser', () =>
    alertOnError(getUser, 'Failed to fetch user', dispatch)
  );

  const cacheData = useMemo(() => {
    return data?.filter((server) => server.type === 'Cache');
  }, [data]);

  const originData = useMemo(() => {
    return data?.filter((server) => server.type === 'Origin');
  }, [data]);

  return (
    <PaddedContent>
      <Box width={'100%'}>
        <Grid container spacing={2}>
          <Grid item xs={12} lg={8} xl={6}>
            <Typography variant={'h4'} pb={2}>
              Origins
            </Typography>
            {originData ? (
              <DirectorCardList
                cardProps={{ authenticated: user }}
                data={originData.map((x) => {
                  return { server: x };
                })}
              />
            ) : (
              <Box>
                <Skeleton variant='rectangular' height={118} />
              </Box>
            )}
          </Grid>
          <Grid item xs={12} lg={8} xl={6}>
            <Typography variant={'h4'} pb={2}>
              Caches
            </Typography>
            {cacheData ? (
              <DirectorCardList
                cardProps={{ authenticated: user }}
                data={cacheData.map((x) => {
                  return { server: x };
                })}
              />
            ) : (
              <Box>
                <Skeleton variant='rectangular' height={118} />
              </Box>
            )}
          </Grid>
          <Grid item xs={12} lg={8} xl={6}>
            <Typography variant={'h4'} pb={2}>
              Namespaces
            </Typography>
            {cacheData ? (
              <NamespaceCardList
                data={
                  namespaces?.map((namespace) => {
                    return { namespace };
                  }) || []
                }
              />
            ) : (
              <Box>
                <Skeleton variant='rectangular' height={118} />
              </Box>
            )}
          </Grid>
          <Grid item xs={12} lg={8} xl={6}>
            <AuthenticatedContent>
              <FederationOverview />
            </AuthenticatedContent>
          </Grid>
        </Grid>
      </Box>
    </PaddedContent>
  );
}
