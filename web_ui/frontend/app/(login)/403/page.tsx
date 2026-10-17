'use client';

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
import { Box, Button, Stack } from '@mui/material';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import AuthPanel from '../components/AuthPanel';

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
    <AuthPanel
      title={'403 Forbidden'}
      description={
        'You do not have permission to access this page. Your login details are shown below; if this is the wrong account, log out and sign in with the correct one.'
      }
    >
      <Stack spacing={2}>
        <Box
          component={'pre'}
          sx={{
            m: 0,
            p: 1.5,
            borderRadius: 2,
            bgcolor: 'grey.100',
            color: 'text.secondary',
            fontFamily: 'monospace',
            fontSize: '0.8rem',
            lineHeight: 1.5,
            textAlign: 'left',
            whiteSpace: 'pre-wrap',
            overflowWrap: 'anywhere',
          }}
        >
          {JSON.stringify(data, null, 2)}
        </Box>
        <Button
          variant='contained'
          size='large'
          fullWidth
          onClick={() =>
            alertOnError(handleLogout, 'Failed to logout', dispatch)
          }
        >
          Logout
        </Button>
      </Stack>
    </AuthPanel>
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
