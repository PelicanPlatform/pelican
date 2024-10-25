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
  Alert,
  Collapse
} from '@mui/material';
import React, { useContext, useMemo } from 'react';

import {
  CardSkeleton
} from '@/components/Namespace';
import { getUser } from '@/helpers/login';
import NamespaceCardList from '@/components/Namespace/NamespaceCardList';
import useSWR from 'swr';
import { CardProps } from '@/components/Namespace/Card';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import DeniedCard from '@/components/Namespace/DeniedCard';
import { getExtendedNamespaces } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';

export default function Home() {

  const dispatch = useContext(AlertDispatchContext)

  const { data } = useSWR(
    'getNamespaces',
    async () => alertOnError(
      getExtendedNamespaces,
      "Couldn't fetch namespaces",
      dispatch
    )
  )
  const { data: user, error } = useSWR(
    'getUser',
    async () => alertOnError(
      getUser,
      "Couldn't fetch user",
      dispatch
    )
  );

  const deniedNamespaces = useMemo(
    () =>
      data?.filter(
        ({ namespace }) => namespace.admin_metadata.status === 'Denied'
      ),
    [data]
  );

  return (
    <Box width={'100%'}>
      <Grid container spacing={2}>
        <Grid item xs={12} lg={6} xl={5}>
          <Typography variant={'h4'}>Namespace Registry</Typography>
        </Grid>
        <Grid item xs={12} lg={8} justifyContent={'space-between'}>
          <AuthenticatedContent redirect={true}>
            <Typography variant={'h6'} py={2}>
              Denied Namespaces
            </Typography>
            {deniedNamespaces !== undefined ? (
              <NamespaceCardList<CardProps>
                data={deniedNamespaces}
                Card={DeniedCard}
                cardProps={{ authenticated: user }}
              />
            ) : (
              <CardSkeleton />
            )}
          </AuthenticatedContent>
        </Grid>
        <Grid item lg={6} xl={8}></Grid>
      </Grid>
    </Box>
  );
}
