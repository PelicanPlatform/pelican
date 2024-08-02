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

import { PutPage } from '@/app/registry/components/PutPage';
import {
  namespaceToCache,
  putGeneralNamespace,
} from '@/app/registry/components/util';
import { Box, Grid, Typography } from '@mui/material';
import React from 'react';

export default function Page() {
  const putCache = async (data: any) => {
    const cache = namespaceToCache(structuredClone(data));
    return putGeneralNamespace(cache);
  };

  return (
    <Box width={'100%'}>
      <Grid container>
        <Grid item xs={12}>
          <Typography variant={'h4'} pb={3}>
            Namespace Registry
          </Typography>
          <Typography variant={'h5'} pb={3}>
            Edit Cache
          </Typography>
        </Grid>
        <Grid item xs={12}>
          <PutPage update={putCache} />
        </Grid>
      </Grid>
    </Box>
  );
}
