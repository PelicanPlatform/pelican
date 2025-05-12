'use client';

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

import React, { useContext } from 'react';
import useApiSWR from '@/hooks/useApiSWR';
import { Box, Button, Typography } from '@mui/material';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';

/**
 * Landing page for 403 error
 * Allows the user to logout and return to the login page
 * @constructor
 */
const Page = () => {
  const dispatch = useContext(AlertDispatchContext);
  const { data } = useApiSWR<any>(
    'Failed to get logged in user',
    'getUser',
    () => fetch('/api/v1.0/auth/whoami')
  );

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        height: '90vh',
      }}
    >
      <Box
        sx={{
          textAlign: 'center',
        }}
      >
        <Typography variant='h1'>403 Forbidden</Typography>
        <Typography variant='body1' sx={{ maxWidth: '80ch' }}>
          You do not have permission to access this page. Your login details are
          exposed below. If this is the wrong account, please log out and log in
          with the correct account.
        </Typography>
        <Box my={2}>
          <Box component={'code'} sx={{ overflowWrap: 'anywhere' }}>
            {JSON.stringify(data)}
          </Box>
        </Box>
        <Button
          variant='contained'
          color='primary'
          onClick={() =>
            alertOnError(handleLogout, 'Failed to logout', dispatch)
          }
        >
          Logout
        </Button>
      </Box>
    </Box>
  );
};

const handleLogout = async () => {
  let response = await fetch('/api/v1.0/auth/logout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  if (response.ok) {
    window.location.href = '/view/';
  }
};

export default Page;
