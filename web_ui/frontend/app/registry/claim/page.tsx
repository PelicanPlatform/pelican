/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

import { Box, Button, Grid, Paper, Skeleton, Typography } from '@mui/material';
import React, { useContext, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { RegistryNamespace } from '@/index';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { claimNamespace, getNamespace } from '@/helpers/api';

// The claim page sits in front of the registration edit form: it is the
// target of the registration link a Pelican server prints to its log after
// auto-registering. After the operator logs in, accepting the claim binds
// the registration to their Pelican user before they continue to the form.
export default function Page() {
  const dispatch = useContext(AlertDispatchContext);
  const router = useRouter();

  const [id, setId] = useState<number | undefined>(undefined);
  const [accessToken, setAccessToken] = useState<string | undefined>(undefined);
  const [fromUrl, setFromUrl] = useState<string | undefined>(undefined);
  const [namespace, setNamespace] = useState<RegistryNamespace | undefined>(
    undefined
  );
  const [claiming, setClaiming] = useState<boolean>(false);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const idParam = urlParams.get('id');
    const accessTokenParam = urlParams.get('access_token');
    const fromUrlParam = urlParams.get('fromUrl');

    if (idParam === null || accessTokenParam === null) {
      dispatch({
        type: 'openAlert',
        payload: {
          title: 'Invalid claim link',
          message:
            "This link is missing the 'id' or 'access_token' parameter. Copy the most recent registration link from your server's log; the token it carries expires after 15 minutes.",
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });
      return;
    }

    const parsedId = parseInt(idParam);
    if (isNaN(parsedId)) {
      dispatch({
        type: 'openAlert',
        payload: {
          title: 'Invalid Namespace ID provided',
          message: 'The Namespace ID in this link is not a valid number.',
          alertProps: {
            severity: 'error',
          },
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });
      return;
    }

    setId(parsedId);
    setAccessToken(accessTokenParam);
    setFromUrl(fromUrlParam || undefined);

    (async () => {
      const response = await alertOnError(
        async () => await getNamespace(parsedId, accessTokenParam),
        "Couldn't get namespace",
        dispatch
      );
      if (response) {
        setNamespace(await response.json());
      }
    })();
  }, [dispatch]);

  // The GET response is the raw registration, so derive the server type from
  // the prefix the same way the registry list page does
  const namespaceType = useMemo(() => {
    if (namespace === undefined) {
      return undefined;
    }
    if (namespace.prefix.startsWith('/caches/')) {
      return 'cache';
    }
    if (namespace.prefix.startsWith('/origins/')) {
      return 'origin';
    }
    return 'namespace';
  }, [namespace]);

  const editUrl = useMemo(() => {
    if (id === undefined || namespaceType === undefined) {
      return undefined;
    }
    const params = new URLSearchParams({ id: id.toString() });
    if (accessToken) {
      params.set('access_token', accessToken);
    }
    if (fromUrl) {
      params.set('fromUrl', fromUrl);
    }
    return `/registry/${namespaceType}/edit/?${params.toString()}`;
  }, [id, namespaceType, accessToken, fromUrl]);

  const claimAndContinue = async () => {
    if (id === undefined || accessToken === undefined || editUrl == undefined) {
      return;
    }
    setClaiming(true);
    const response = await alertOnError(
      async () => await claimNamespace(id, accessToken),
      "Couldn't claim the registration",
      dispatch
    );
    setClaiming(false);
    if (response) {
      router.push(editUrl);
    }
  };

  return (
    <AuthenticatedContent redirect={true} boxProps={{ width: '100%' }}>
      <Grid container spacing={2}>
        <Grid
          size={{
            xs: 12,
            lg: 6,
          }}
        >
          {namespace ? (
            <Paper sx={{ p: 3 }} elevation={3}>
              <Typography variant={'h5'} pb={2}>
                Claim Registration
              </Typography>
              <Typography variant={'body1'} pb={2}>
                A Pelican server registered itself with this federation and
                needs an owner. Accepting makes your account the owner of this
                registration so you can complete and manage it.
              </Typography>
              <Box pb={2}>
                <Typography variant={'subtitle2'}>Prefix</Typography>
                <Typography variant={'body2'} pb={1}>
                  {namespace.prefix}
                </Typography>
                <Typography variant={'subtitle2'}>Site Name</Typography>
                <Typography variant={'body2'}>
                  {namespace.admin_metadata?.site_name || '—'}
                </Typography>
              </Box>
              <Button
                variant={'contained'}
                disabled={claiming}
                onClick={claimAndContinue}
              >
                Accept and Continue
              </Button>
            </Paper>
          ) : (
            <Skeleton variant='rectangular' width='100%' height={300} />
          )}
        </Grid>
      </Grid>
    </AuthenticatedContent>
  );
}
