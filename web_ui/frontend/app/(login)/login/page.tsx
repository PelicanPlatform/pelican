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
  Grow,
  Typography,
  Button,
  Collapse,
  Skeleton,
} from '@mui/material';
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
  getErrorMessage,
  getOauthEnabledServers,
} from '@/helpers/util';
import { login } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';

const AdminLogin = () => {

  const dispatch = useContext(AlertDispatchContext);

  const router = useRouter();
  const { mutate } = useSWR('getUser', getUser);

  let [password, setPassword] = useState<string>('');
  let [loading, setLoading] = useState(false);
  const [toggled, setToggled] = useState(false);

  const { data: enabledServers } = useSWR<ServerType[] | undefined>(
    'getEnabledServers',
    async () => await alertOnError(
      getEnabledServers,
      "Could not get enabled servers",
      dispatch
    )
  );
  const { data: oauthServers } = useSWR<ServerType[] | undefined>(
    'getOauthEnabledServers',
    async () => await alertOnError(
      getOauthEnabledServers,
      "Could not get oauth enabled servers",
      dispatch
    ),
    { fallbackData: [] }
  );

  const serverIntersect = useMemo(() => {
    if (enabledServers && oauthServers) {
      return enabledServers.filter((server) => oauthServers.includes(server));
    }
  }, [enabledServers, oauthServers]);

  async function submit(password: string) {
    setLoading(true);

    const response = await alertOnError(
      async () => await login(password),
      "Could not login",
      dispatch
    )
    if (response) {
      await mutate(getUser);

      const url = new URL(window.location.href);
      let returnUrl = url.searchParams.get('returnURL') || '';
      returnUrl = returnUrl.replace(`/view`, '');
      router.push(returnUrl ? returnUrl : '../');
    } else {
      setLoading(false);
    }
  }

  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    submit(password);
  }

  const LoginComponent = (
    <form onSubmit={onSubmit} action='#'>
      <Box display={'flex'} justifyContent={'center'}>
        <PasswordInput
          FormControlProps={{
            sx: { width: '50%' },
          }}
          TextFieldProps={{
            InputProps: {
              sx: { width: '50%' },
              onChange: (e) => {
                setPassword(e.target.value);
              },
            },
          }}
        />
      </Box>
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
        <Box m={'auto'}>
          <Button
            size={'small'}
            variant={'text'}
            onClick={() => setToggled(!toggled)}
          >
            Server Admin Login
          </Button>
        </Box>
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
    async () => await alertOnError(
      getEnabledServers,
      "Could not get enabled servers",
      dispatch
    )
  );
  const { data: oauthServers } = useSWR<ServerType[] | undefined>(
    'getOauthEnabledServers',
    async () => await alertOnError(
      getOauthEnabledServers,
      "Could not determine if the active server had OAuth enabled",
      dispatch
    ),
    { fallbackData: [] }
  );

  useEffect(() => {
    const url = new URL(window.location.href);
    const returnUrl = url.searchParams.get('returnURL') || '';
    const encodedReturnUrl = encodeURIComponent(returnUrl);
    setReturnUrl(encodedReturnUrl);
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
            <Typography textAlign={'center'} variant={'h6'} component={'p'}>
              Administer your Pelican Platform
            </Typography>
          </Box>
        </Box>
        <Box mx={'auto'}>
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
          {serverIntersect && <AdminLogin />}
          {!serverIntersect && (
            <Skeleton
              variant={'rectangular'}
              height={90}
              width={400}
              sx={{ borderRadius: 2 }}
            />
          )}
        </Box>
      </Box>
    </>
  );
}
