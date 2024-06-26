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

import React, { useState, useEffect } from 'react';
import { Box, Container, Grid, Skeleton, Typography } from '@mui/material';
import Link from 'next/link';
import useSWR from 'swr';
import { getEnabledServers } from '@/helpers/util';
import { ServerType } from '@/index';

function TextCenteredBox({ text }: { text: string }) {
  return (
    <Box
      sx={{
        aspectRatio: 1,
        width: '100%',
        display: 'flex',
        textTransform: 'capitalize',
        bgcolor: 'primary.light',
        borderRadius: '1rem',
      }}
    >
      <Box m={'auto'}>
        <Typography variant={'h4'} align={'center'}>
          {text}
        </Typography>
      </Box>
    </Box>
  );
}

export default function Home() {
  const { data: enabledServers, isLoading } = useSWR<ServerType[]>(
    'getEnabledServers',
    getEnabledServers
  );

  return (
    <Box width={'100%'} pt={5}>
      <Container maxWidth={'xl'}>
        <Typography pb={5} textAlign={'center'} variant={'h3'}>
          Pelican Services
        </Typography>
        <Grid container justifyContent={'center'} spacing={2}>
          {isLoading && (
            <Grid item xs={2}>
              <Skeleton
                variant={'rectangular'}
                width={150}
                height={150}
                sx={{ borderRadius: 2 }}
              />
            </Grid>
          )}
          {enabledServers &&
            enabledServers.map((service) => {
              return (
                <Grid key={service} item xs={2}>
                  <Link href={`./${service}/`}>
                    <TextCenteredBox text={service} />
                  </Link>
                </Grid>
              );
            })}
        </Grid>
      </Container>
    </Box>
  );
}
