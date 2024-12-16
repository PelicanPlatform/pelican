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

import { useState, Suspense } from 'react';
import {
  Box,
  IconButton,
  Grid,
  Tooltip,
  Typography,
  Skeleton,
} from '@mui/material';
import { Key, CheckCircle } from '@mui/icons-material';

import RateGraph from '@/components/graphs/RateGraph';
import StatusBox from '@/components/StatusBox';
import { DataExportTable } from '@/components/DataExportTable';
import { TimeDuration } from '@/components/graphs/prometheus';
import FederationOverview from '@/components/FederationOverview';
import { User } from '@/index';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { getErrorMessage } from '@/helpers/util';

export default function Home() {
  const [copied, setCopied] = useState(false);

  const handleClick = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const keyResponse = await fetch('/.well-known/issuer.jwks');
    if (keyResponse.ok) {
      const data = await keyResponse.json();
      await navigator.clipboard.writeText(JSON.stringify(data));
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 3000);
    } else {
      const errMsg = await getErrorMessage(keyResponse);
      console.error(errMsg);
    }
  };

  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin']}>
      <Box width={'100%'}>
        <Grid container spacing={2}>
          <Grid item xs={12} lg={6}>
            <Typography variant='h4' mb={2}>
              Status
            </Typography>
            <StatusBox />
          </Grid>
          <Grid item xs={12} lg={6}>
            <Box
              display={'flex'}
              flexDirection={'row'}
              justifyContent={'space-between'}
              alignItems={'center'}
            >
              <Typography variant={'h4'} component={'h2'} mb={2}>
                Data Exports
              </Typography>
              <Tooltip title={'Copy Pelican public key'}>
                {copied ? (
                  <IconButton color='success'>
                    <CheckCircle />
                  </IconButton>
                ) : (
                  <IconButton onClick={handleClick}>
                    <Key />
                  </IconButton>
                )}
              </Tooltip>
            </Box>
            <Suspense fallback={<Skeleton />}>
              <DataExportTable />
            </Suspense>
          </Grid>
          <Grid item xs={12} lg={6}>
            <FederationOverview />
          </Grid>
        </Grid>
      </Box>
    </AuthenticatedContent>
  );
}
