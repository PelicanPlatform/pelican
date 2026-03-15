/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  TextField,
  Typography,
} from '@mui/material';
import { useSearchParams, useRouter } from 'next/navigation';
import { Suspense, useCallback, useEffect, useRef, useState } from 'react';

import { isLoggedIn } from '@/helpers/login';

type DeviceStatus = 'idle' | 'loading' | 'approved' | 'denied' | 'error';

/** Strip everything except alphanumeric chars, uppercase, limit to 8. */
const normalizeCode = (input: string): string =>
  input
    .replace(/[^A-Za-z0-9]/g, '')
    .toUpperCase()
    .slice(0, 8);

/** Format raw 8-char code as XXXX-XXXX for display. */
const formatCode = (raw: string): string =>
  raw.length > 4 ? `${raw.slice(0, 4)}-${raw.slice(4)}` : raw;

/**
 * DeviceVerifyInner contains the actual page logic. It is wrapped in
 * <Suspense> because useSearchParams() requires it in Next.js app router.
 */
function DeviceVerifyInner() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const namespace = searchParams.get('namespace') || '';
  const initialCode = searchParams.get('user_code') || '';

  const [rawCode, setRawCode] = useState(normalizeCode(initialCode));
  const [csrfToken, setCsrfToken] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [clientName, setClientName] = useState('');
  const [status, setStatus] = useState<DeviceStatus>('idle');
  const [errorMsg, setErrorMsg] = useState('');
  const [checkingAuth, setCheckingAuth] = useState(true);

  const codeComplete = rawCode.length === 8;
  const apiBase = `/api/v1.0/issuer/ns${namespace}/device`;

  // Fetch CSRF token and (when a code is supplied) scopes / client info.
  // Returns true if a user_code was provided and resolved to a valid session.
  const fetchDeviceInfo = useCallback(
    async (code?: string): Promise<boolean> => {
      const params = code ? `?user_code=${encodeURIComponent(code)}` : '';
      const resp = await fetch(apiBase + params);
      if (!resp.ok) {
        throw new Error(`Failed to load device verification (${resp.status})`);
      }
      const data = await resp.json();
      setCsrfToken(data.csrf_token || '');
      setScopes(data.scopes || []);
      setClientName(data.client_name || '');
      // If a code was requested but no scopes came back, it's invalid.
      return !code || (data.scopes && data.scopes.length > 0);
    },
    [apiBase]
  );

  // On mount: check auth, then fetch CSRF (+ scopes if initial code is complete).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      setCheckingAuth(true);
      try {
        const loggedIn = await isLoggedIn();
        if (!loggedIn) {
          const returnURL = window.location.pathname + window.location.search;
          router.push(`/login?returnURL=${encodeURIComponent(returnURL)}`);
          return;
        }
        if (cancelled) return;
        const code =
          normalizeCode(initialCode).length === 8
            ? formatCode(normalizeCode(initialCode))
            : undefined;
        const valid = await fetchDeviceInfo(code);
        if (!cancelled && code && !valid) {
          setStatus('error');
          setErrorMsg('Invalid or expired user code');
        }
      } catch (e: unknown) {
        if (!cancelled) {
          setStatus('error');
          setErrorMsg(e instanceof Error ? e.message : 'Failed to initialize');
        }
      } finally {
        if (!cancelled) setCheckingAuth(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // When the user types/pastes a different complete code, refresh scopes.
  const lastFetchedCode = useRef(normalizeCode(initialCode));
  useEffect(() => {
    if (checkingAuth) return;
    // Any code change clears previous errors.
    setStatus((s) => (s === 'error' ? 'idle' : s));
    setErrorMsg('');
    if (codeComplete && rawCode !== lastFetchedCode.current) {
      lastFetchedCode.current = rawCode;
      fetchDeviceInfo(formatCode(rawCode))
        .then((valid) => {
          if (!valid) {
            setStatus('error');
            setErrorMsg('Invalid or expired user code');
          }
        })
        .catch(() => {
          setScopes([]);
          setClientName('');
        });
    } else if (!codeComplete) {
      setScopes([]);
      setClientName('');
    }
  }, [rawCode, codeComplete, checkingAuth, fetchDeviceInfo]);

  const submitAction = async (action: 'approve' | 'deny') => {
    setStatus('loading');
    setErrorMsg('');

    try {
      const resp = await fetch(apiBase, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_code: formatCode(rawCode),
          action,
          csrf_token: csrfToken,
        }),
      });
      const data = await resp.json();

      if (!resp.ok || data.status === 'error') {
        setStatus('error');
        setErrorMsg(data.error || 'Request failed');
        return;
      }

      setStatus(data.status === 'approved' ? 'approved' : 'denied');
    } catch (e: unknown) {
      setStatus('error');
      setErrorMsg(e instanceof Error ? e.message : 'Request failed');
    }
  };

  if (checkingAuth) {
    return (
      <Box display='flex' justifyContent='center' mt={8}>
        <CircularProgress />
      </Box>
    );
  }

  if (status === 'approved') {
    return (
      <Box m='auto' mt='15vh' maxWidth={480} textAlign='center'>
        <Typography variant='h4' gutterBottom>
          Device Authorized
        </Typography>
        <Alert severity='success' sx={{ mt: 2 }}>
          User Code Accepted — you may close this window and return to your
          device.
        </Alert>
      </Box>
    );
  }

  if (status === 'denied') {
    return (
      <Box m='auto' mt='15vh' maxWidth={480} textAlign='center'>
        <Typography variant='h4' gutterBottom>
          Authorization Denied
        </Typography>
        <Alert severity='info' sx={{ mt: 2 }}>
          The device authorization request was denied. You may close this
          window.
        </Alert>
      </Box>
    );
  }

  return (
    <Box m='auto' mt='15vh' maxWidth={480}>
      <Typography variant='h4' gutterBottom textAlign='center'>
        Device Authorization
      </Typography>
      <Typography variant='body1' sx={{ mb: 3 }} textAlign='center'>
        {clientName
          ? `"${clientName}" is requesting access to your account.`
          : 'Enter the code displayed on your device to authorize access.'}
      </Typography>

      {scopes.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant='subtitle2' gutterBottom>
            Requested permissions:
          </Typography>
          <Box display='flex' flexWrap='wrap' gap={1}>
            {scopes.map((scope) => (
              <Chip key={scope} label={scope} variant='outlined' />
            ))}
          </Box>
        </Box>
      )}

      {status === 'error' && (
        <Alert severity='error' sx={{ mb: 2 }}>
          {errorMsg}
        </Alert>
      )}

      <Box component='form' onSubmit={(e) => e.preventDefault()}>
        <TextField
          label='User Code'
          placeholder='XXXX-XXXX'
          value={formatCode(rawCode)}
          onChange={(e) => setRawCode(normalizeCode(e.target.value))}
          fullWidth
          inputProps={{
            maxLength: 9,
            style: {
              textAlign: 'center',
              fontSize: '1.5rem',
              letterSpacing: '0.2em',
            },
          }}
          sx={{ mb: 3 }}
          autoFocus={!initialCode}
        />
        <Box display='flex' gap={2} justifyContent='center'>
          <Button
            variant='contained'
            color='primary'
            size='large'
            onClick={() => submitAction('approve')}
            disabled={status === 'loading' || !codeComplete}
          >
            {status === 'loading' ? (
              <CircularProgress size={24} />
            ) : (
              'Authorize'
            )}
          </Button>
          <Button
            variant='outlined'
            color='error'
            size='large'
            onClick={() => submitAction('deny')}
            disabled={status === 'loading' || !codeComplete}
          >
            Deny
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default function DeviceVerifyPage() {
  return (
    <Suspense
      fallback={
        <Box display='flex' justifyContent='center' mt={8}>
          <CircularProgress />
        </Box>
      }
    >
      <DeviceVerifyInner />
    </Suspense>
  );
}
