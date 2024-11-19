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
  Collapse,
  Alert,
  Skeleton,
} from '@mui/material';
import React, {
  ReactNode,
  Suspense,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { RegistryNamespace, Alert as AlertType } from '@/index';
import Form from '@/app/registry/components/Form';
import { submitNamespaceForm } from '@/app/registry/components/util';
import { getNamespace } from '@/helpers/api';
import { NamespaceFormPage } from '@/app/registry/components';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';

const PutPage = ({ update }: NamespaceFormPage) => {
  const [id, setId] = useState<number | undefined>(undefined);
  const [fromUrl, setFromUrl] = useState<URL | undefined>(undefined);
  const [namespace, setNamespace] = useState<RegistryNamespace | undefined>(undefined);

  const dispatch = useContext(AlertDispatchContext);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const id = urlParams.get('id');
    const fromUrl = urlParams.get('fromUrl');
    const accessToken = urlParams.get('access_token');

    if (id === null) {
      dispatch({
        type: 'openAlert',
        payload: {
          title: 'No Namespace ID Provided',
          message:
            "Your URL should contain a query parameter 'id' with the ID of the namespace you want to edit",
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });
      return;
    }

    try {
      if (fromUrl != undefined) {
        const parsedUrl = new URL(fromUrl);
        setFromUrl(parsedUrl);
      }
    } catch (e) {
      dispatch({
        type: 'openAlert',
        payload: {
          title: 'Invalid fromUrl provided',
          message:
            'The `fromUrl` parameter provided is not a valid URL, this will only impact your redirection on completion of this form',
          alertProps: {
            severity: 'warning',
          },
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });
    }

    try {
      setId(parseInt(id));
    } catch (e) {
      dispatch({
        type: 'openAlert',
        payload: {
          title: 'Invalid Namespace ID provided',
          message:
            'The Namespace Id provided is not a valid number. Please report this issue, as well as what link directed you here.',
          alertProps: {
            severity: 'error',
          },
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });
    }

    (async () => {
      if (id !== undefined) {
        const response = await alertOnError(
          async () => await getNamespace(id, accessToken || undefined),
          "Couldn't get namespace",
          dispatch
        );
        if (response) {
          setNamespace(await response.json());
        }
      }
    })();
  }, []);

  return (
    <AuthenticatedContent redirect={true} boxProps={{ width: '100%' }}>
      <Grid container spacing={2}>
        <Grid item xs={12} lg={8}>
          {namespace ? (
            <Form
              namespace={namespace}
              onSubmit={async (data) => {
                let namespace = { ...data, id: id };
                await alertOnError(
                  async () =>
                    await submitNamespaceForm(namespace, fromUrl, update),
                  'Failed to update namespace',
                  dispatch
                );
              }}
            />
          ) : (
            <Skeleton variant='rectangular' width='100%' height={400} />
          )}
        </Grid>
        <Grid item lg={4}></Grid>
      </Grid>
    </AuthenticatedContent>
  );
};

export { PutPage };
