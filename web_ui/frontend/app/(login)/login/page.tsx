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
  Button,
  Collapse,
  Divider,
  Skeleton,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import { useRouter } from 'next/navigation';
import { useContext, useEffect, useMemo, useState } from 'react';

import AuthPanel from '../components/AuthPanel';
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

// safeSameOriginPath validates a candidate returnURL and returns a
// same-origin, path-only destination that is safe to hand to
// window.location.href — or null if the candidate isn't safe.
//
// It parses the candidate against the current origin and requires the
// resolved origin to match ours, which rejects:
//   - absolute URLs to another site ("https://evil.example"),
//   - protocol-relative "//host" and the "/\host" backslash variant that
//     browsers normalize into a protocol-relative URL (open redirect),
//   - "javascript:" URLs, which parse to an opaque (non-matching) origin
//     (DOM-XSS via a script-scheme navigation).
//
// Crucially it returns only the parsed URL's path components
// (pathname+search+hash), never the raw attacker-controlled string, so
// the navigation sink can never receive a scheme or a foreign host. That
// closes both the open-redirect and the client-side-XSS vectors.
const safeSameOriginPath = (raw: string): string | null => {
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) {
    return null;
  }
  try {
    const parsed = new URL(raw, window.location.origin);
    if (parsed.origin !== window.location.origin) {
      return null;
    }
    return parsed.pathname + parsed.search + parsed.hash;
  } catch {
    return null;
  }
};

/**
 * Username + password sign-in.
 *
 * `collapsible` is true when OAuth is the primary route for this server, in
 * which case the form is folded behind a link so the page leads with the
 * button most callers want. The parent already knows which servers are
 * enabled and which have OAuth; it used to be fetched a second time here.
 */
const PasswordLogin = ({ collapsible }: { collapsible: boolean }) => {
  const dispatch = useContext(AlertDispatchContext);

  const router = useRouter();
  const { mutate } = useSWR('getUser', getUser);

  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [toggled, setToggled] = useState(false);

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
      } else {
        // Otherwise it's a path outside the SPA route table, so use a full
        // navigation — but only to a validated same-origin path. safePath
        // is either the sanitized path-only destination or null; when
        // null we fall back to the landing page rather than navigating to
        // an attacker-controlled value. Use an absolute path for the
        // fallback: relative hrefs to router.push behave inconsistently
        // with Next's basePath (a non-admin with no returnURL appeared to
        // "go nowhere" otherwise).
        const safePath = returnUrl ? safeSameOriginPath(returnUrl) : null;
        if (safePath) {
          window.location.href = safePath;
        } else {
          router.push('/');
        }
      }
    } else {
      setLoading(false);
    }
  }

  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    submit(username, password);
  }

  const form = (
    <form onSubmit={onSubmit} action='#'>
      <Stack spacing={2}>
        <TextField
          label='Username'
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete='username'
          fullWidth
        />
        <PasswordInput
          TextFieldProps={{
            label: 'Password',
            onChange: (e) => setPassword(e.target.value),
          }}
        />
        <LoadingButton
          variant='contained'
          size='large'
          fullWidth
          type={'submit'}
          loading={loading}
        >
          <span>Login</span>
        </LoadingButton>
      </Stack>
    </form>
  );

  if (!collapsible) {
    return form;
  }

  return (
    <Stack spacing={1.5}>
      <Divider>
        <Typography variant={'caption'} color={'text.secondary'}>
          or
        </Typography>
      </Divider>
      <Button
        size={'small'}
        variant={'text'}
        onClick={() => setToggled(!toggled)}
        aria-expanded={toggled}
        endIcon={
          toggled ? (
            <ExpandLess fontSize={'small'} />
          ) : (
            <ExpandMore fontSize={'small'} />
          )
        }
        sx={{ alignSelf: 'center' }}
      >
        Username + password login
      </Button>
      <Collapse in={toggled}>{form}</Collapse>
    </Stack>
  );
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

  // OAuth is offered whenever any enabled server has it configured. The
  // password form yields to it -- folding away behind a link -- only on the
  // servers whose accounts are ordinarily OAuth-backed; a director keeps the
  // form open because its local admin account is the usual way in.
  const oauthEnabled =
    !!serverIntersect &&
    (['registry', 'origin', 'cache', 'director'] as ServerType[]).some((s) =>
      serverIntersect.includes(s)
    );
  const passwordCollapsible =
    !!serverIntersect &&
    (['registry', 'origin', 'cache'] as ServerType[]).some((s) =>
      serverIntersect.includes(s)
    );

  return (
    <AuthPanel title={'Login'} description={'Administer your Pelican Platform'}>
      {!serverIntersect && (
        <Stack spacing={2} aria-busy={true} aria-label={'Loading sign-in'}>
          <Skeleton variant={'rounded'} height={48} />
          <Skeleton variant={'rounded'} height={48} />
        </Stack>
      )}
      {serverIntersect && (
        <Stack spacing={2}>
          {oauthEnabled && (
            <Button
              size={'large'}
              fullWidth
              href={`/api/v1.0/auth/oauth/login?nextUrl=${returnUrl ? returnUrl : '/'}`}
              variant={'contained'}
            >
              Login with OAuth
            </Button>
          )}
          <PasswordLogin collapsible={passwordCollapsible} />
        </Stack>
      )}
    </AuthPanel>
  );
}

const getReturnUrl = (url: string) => {
  const currentUrl = new URL(url);
  return (
    currentUrl.searchParams.get('returnURL') ||
    currentUrl.searchParams.get('nextUrl')
  );
};
