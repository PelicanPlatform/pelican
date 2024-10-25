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

import { Box, Grid, Collapse, Alert, Skeleton } from '@mui/material';
import React, { useContext, useEffect, useState } from 'react';
import Form from '@/app/registry/components/Form';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { submitNamespaceForm } from '@/app/registry/components/util';
import { NamespaceFormPage } from '@/app/registry/components';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';

const PostPage = ({ update }: NamespaceFormPage) => {

  const dispatch = useContext(AlertDispatchContext);

  const [fromUrl, setFromUrl] = useState<URL | undefined>(undefined);

  useEffect(() => {
    (async () => {
      const urlParams = new URLSearchParams(window.location.search);
      const fromUrl = urlParams.get('fromUrl');

      if (fromUrl != undefined) {
        const parsedUrl = await alertOnError<URL>(
          () => new URL(fromUrl),
          "Failed to parse URL",
          dispatch
        );
        if (parsedUrl) {
          setFromUrl(parsedUrl);
        }
      }
    })()
  }, []);

  return (
    <AuthenticatedContent redirect={true} boxProps={{ width: '100%' }}>
      <Grid container spacing={2}>
        <Grid item xs={12} lg={7} justifyContent={'space-between'}>
          <Form
            onSubmit={async (namespace) => {
              await alertOnError(
                async () => await submitNamespaceForm(namespace, fromUrl, update),
                "Failed to update namespace",
                dispatch
              )
            }}
          />
        </Grid>
        <Grid item lg={2}></Grid>
      </Grid>
    </AuthenticatedContent>
  );
};

export { PostPage };
