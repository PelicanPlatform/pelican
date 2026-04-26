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

import { Box, Button, Collapse, Skeleton, Stack, TextField, Typography } from '@mui/material';
import { useRouter } from 'next/navigation';
import { useContext, useEffect, useMemo, useState } from 'react';

import LoadingButton from '../components/LoadingButton';
import PasswordInput from '../components/PasswordInput';
import useSWR from 'swr';
import { getUser } from '@/helpers/login';
import { ServerType } from '@/index';
import {
  alertOnError,
  getEnabledServers,
  getOauthEnabledServers,
} from '@/helpers/util';
import { login } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';

const PasswordLogin = () => {
  const dispatch = useContext(AlertDispatchContext);

  const router = useRouter();
  const { mutate } = useSWR('getUser', getUser);

  let [username, setUsername] = useState<string>('');
  let [password, setPassword] = useState<string>('');
  let [loading, setLoading] = useState(false);
  const [toggled, setToggled] = useState(false);

  const { data: enabledServers } = useSWR<ServerType[] | undefined>(
    'getEnabledServers',
    async () =>
      await alertOnError(
        getEnabledServers,
        'Could not get enabled servers',
        dispatch
      )
  );
  const { data: oauthServers } = useSWR<ServerType[] | undefined>(
    'getOauthEnabledServers',
    async () =>
      await alertOnError(
        getOauthEnabledServers,
        'Could not get oauth enabled servers',
        dispatch
      ),
    { fallbackData: [] }
  );

  const serverIntersect = useMemo(() => {
    if (enabledServers && oauthServers) {
      return enabledServers.filter((server) => oauthServers.includes(server));
    }
  }, [enabledServers, oauthServers]);

  async function submit(username: string, password: string) {
    setLoading(true);

    const response = await alertOnError(
      async () => await login(password, username),
      'Could not login',
      dispatch
    );
    if (response) {
      await mutate(getUser);

      const returnUrl = getReturnUrl(window.location.href);

      // If the returnUrl is going to the Pelican web app use the app router.
      // The router applies basePath ("/view") on its own, so strip it here.
      if (returnUrl && returnUrl.includes('/view')) {
        router.push(returnUrl.replace(`/view`, '') || '/');

        // If the returnUrl is some other relative path, use a full navigation
        // since it's outside the SPA's route table.
      } else if (returnUrl && returnUrl.startsWith('/')) {
        window.location.href = returnUrl;

        // Default to the landing page. Use an absolute path: relative hrefs
        // to router.push behave inconsistently with Next's basePath, which
        // is why a non-admin (no returnURL set) appeared to "go nowhere".
      } else {
        router.push('/');
      }
    } else {
      setLoading(false);
    }
  }

  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    submit(username, password);
  }

  const LoginComponent = (
    <form onSubmit={onSubmit} action='#'>
      <Stack spacing={1.5}>
        <TextField
          label='Username'
          size='small'
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete='username'
          fullWidth
        />
        <PasswordInput
          TextFieldProps={{
            label: 'Password',
            InputProps: {
              onChange: (e) => {
                setPassword(e.target.value);
              },
            },
          }}
        />
        <Box display={'flex'} flexDirection={'column'}>
          <LoadingButton
            variant='outlined'
            sx={{ margin: 'auto' }}
            color={'primary'}
            type={'submit'}
            loading={loading}
          >
            <span>Login</span>
          </LoadingButton>
        </Box>
      </Stack>
    </form>
  );

  if (
    serverIntersect &&
    (serverIntersect.includes('registry') ||
      serverIntersect.includes('origin') ||
      serverIntersect.includes('cache'))
  ) {
    return (
      <Box display={'flex'} flexDirection={'column'} justifyContent={'center'}>
        <Button
          size={'small'}
          variant={'text'}
          onClick={() => setToggled(!toggled)}
        >
          Username + password login
        </Button>
        <Collapse in={toggled}>{LoginComponent}</Collapse>
      </Box>
    );
  }

  return LoginComponent;
};

export default function Home() {
  const dispatch = useContext(AlertDispatchContext);

  const [returnUrl, setReturnUrl] = useState<string | undefined>(undefined);
  const { data: enabledServers } = useSWR<ServerType[] | undefined>(
    'getEnabledServers',
    async () =>
      await alertOnError(
        getEnabledServers,
        'Could not get enabled servers',
        dispatch
      )
  );
  const { data: oauthServers } = useSWR<ServerType[] | undefined>(
    'getOauthEnabledServers',
    async () =>
      await alertOnError(
        getOauthEnabledServers,
        'Could not determine if the active server had OAuth enabled',
        dispatch
      ),
    { fallbackData: [] }
  );

  useEffect(() => {
    const returnUrl = getReturnUrl(window.location.href);
    if (returnUrl) {
      const encodedReturnUrl = encodeURIComponent(returnUrl);
      setReturnUrl(encodedReturnUrl);
    }
  }, []);

  const serverIntersect = useMemo(() => {
    if (enabledServers && oauthServers) {
      return enabledServers.filter((server) => oauthServers.includes(server));
    }
  }, [enabledServers, oauthServers]);

  return (
    <>
      <Box m={'auto'} mt={'20vh'} display={'flex'} flexDirection={'column'}>
        <Box>
          <Typography textAlign={'center'} variant={'h3'} component={'h3'}>
            Login
          </Typography>
          <Box color={'grey'} mt={1} mb={2}>
            <Typography
              variant={'h6'}
              component={'p'}
              sx={{
                textAlign: 'center',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              Administer your Pelican Platform
            </Typography>
          </Box>
        </Box>
        {serverIntersect &&
          (serverIntersect.includes('registry') ||
            serverIntersect.includes('origin') ||
            serverIntersect.includes('cache') ||
            serverIntersect.includes('director')) && (
            <>
              <Box display={'flex'} justifyContent={'center'} mb={1}>
                <Button
                  size={'large'}
                  href={`/api/v1.0/auth/oauth/login?nextUrl=${returnUrl ? returnUrl : '/'}`}
                  variant={'contained'}
                >
                  Login with OAuth
                </Button>
              </Box>
            </>
          )}
        {serverIntersect && <PasswordLogin />}
        {!serverIntersect && (
          <Skeleton
            variant={'rectangular'}
            height={90}
            width={'100%'}
            sx={{ borderRadius: 2 }}
          />
        )}
      </Box>
    </>
  );
}

const getReturnUrl = (url: string) => {
  const currentUrl = new URL(url);
  return (
    currentUrl.searchParams.get('returnURL') ||
    currentUrl.searchParams.get('nextUrl')
  );
};
