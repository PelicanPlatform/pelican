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

import React, { Suspense, useContext, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Divider,
  Paper,
  Skeleton,
  Stack,
  Typography,
} from '@mui/material';
import { useSearchParams } from 'next/navigation';

import MarkdownRender from '@/components/MarkdownRender';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { MeService } from '@/helpers/api';
import { API_V1_BASE_URL } from '@/helpers/api/constants';
import { getUser } from '@/helpers/login';

// AUPDocument matches the backend's web_ui/aup.go AUPDocumentResp struct.
// Shared shape: callers (this page, AuthenticatedContent's gate) use the
// same fields so a future content-rich AUP renderer doesn't need a
// second probe.
export interface AUPDocument {
  content: string;
  version: string;
  source: 'default' | 'operator' | 'db' | 'none';
  lastUpdated?: string;
  canonicalUrl?: string;
}

// resolveReturnURL accepts a returnURL query string only when it is a
// same-origin path. Without this guard, a malicious link could send
// signed users to an attacker-controlled domain after acceptance.
const resolveReturnURL = (raw: string | null): string => {
  if (!raw) return '/';
  if (!raw.startsWith('/') || raw.startsWith('//')) return '/';
  return raw;
};

// Page wraps Body in a Suspense boundary because useSearchParams (used
// by Body) is a suspending hook under Next 15 + output:export, and
// the build prerender step refuses to render the page without the
// boundary.
const Page: React.FC = () => (
  <Suspense
    fallback={
      <Container maxWidth='md' sx={{ py: 4 }}>
        <Skeleton variant='rounded' width='100%' height={240} />
      </Container>
    }
  >
    <Body />
  </Suspense>
);

const Body: React.FC = () => {
  const searchParams = useSearchParams();
  const returnURL = resolveReturnURL(searchParams.get('returnURL'));
  // gating === true when the caller arrived here via the
  // RequireAUPCompliance redirect (AuthenticatedContent only sets
  // returnURL when it's bouncing the user). The page renders an
  // "you must accept this to continue" preamble in that case so it's
  // obvious why the AUP is in their face.
  const gating = !!searchParams.get('returnURL');

  const dispatch = useContext(AlertDispatchContext);

  const [doc, setDoc] = useState<AUPDocument | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Whether the caller is logged in. Determines whether to show the
  // "I agree" button (logged in) or just the read-only AUP (anonymous).
  // Anonymous reads are useful for prospective users who want to see
  // the policy before signing up.
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [agreeing, setAgreeing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const r = await fetch(`${API_V1_BASE_URL}/aup`);
        if (!r.ok) {
          if (!cancelled) {
            setError(
              r.status === 404
                ? 'No Acceptable Use Policy is configured on this server.'
                : `Failed to load AUP (HTTP ${r.status}).`
            );
          }
          return;
        }
        const body = (await r.json()) as AUPDocument;
        if (!cancelled) setDoc(body);
      } catch (e) {
        if (!cancelled)
          setError(e instanceof Error ? e.message : 'Failed to load AUP');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    // Probe auth state — getUser is the cheap "are you logged in" check
    // already used elsewhere in the app.
    void (async () => {
      try {
        const who = await getUser();
        if (!cancelled) setAuthed(!!who?.authenticated);
      } catch {
        if (!cancelled) setAuthed(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const agree = async () => {
    if (!doc) return;
    setAgreeing(true);
    // Use passError so we can distinguish success from "alertOnError
    // already showed the user the error and swallowed it." Without
    // this, recordAUP's void return would always resolve to undefined
    // and the success branch below would never fire.
    let success = false;
    try {
      await alertOnError(
        () => MeService.recordAUP(doc.version),
        'Failed to record AUP agreement',
        dispatch,
        true
      );
      success = true;
    } catch {
      // alertOnError dispatched the error UI; nothing more to do.
    }
    setAgreeing(false);
    if (!success) return;

    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message: 'AUP agreement recorded',
        autoHideDuration: 3000,
        alertProps: { severity: 'success' },
      },
    });
    // Bounce back to the page that originally sent the user here,
    // or to the home page if there was no returnURL.
    //
    // We use window.location.assign — NOT router.replace — because
    // returnURL is captured as a full URL (e.g. "/view/origin/") that
    // already includes Next.js's basePath. router.replace would
    // automatically prepend the basePath again, producing
    // "/view/view/origin/" → 404. Falling out to window.location
    // also triggers a fresh document load, which is exactly what we
    // want here: the previous page's /whoami response said
    // requires_aup=true and was probably cached; a full reload
    // re-fetches it under the freshly-signed state.
    window.location.assign(returnURL);
  };

  return (
    <Container maxWidth='md' sx={{ py: 4 }}>
      <Stack spacing={3}>
        {gating && authed && (
          <Alert severity='info'>
            You must accept the Acceptable Use Policy below before
            continuing. After accepting, you'll be returned to where
            you were headed.
          </Alert>
        )}
        <Box display='flex' alignItems='center' gap={1}>
          <Typography variant='h4'>Acceptable Use Policy</Typography>
          {doc?.source === 'default' && (
            // Operators are expected to replace the embedded default
            // with their own customized copy. Surface the source so it's
            // obvious when a deployment hasn't done that yet.
            <Chip
              size='small'
              variant='outlined'
              label='Pelican default'
              color='warning'
            />
          )}
          {doc && (
            <Chip
              size='small'
              variant='outlined'
              sx={{ fontFamily: 'monospace' }}
              label={`v ${doc.version}`}
            />
          )}
        </Box>

        {loading && (
          <Box display='flex' alignItems='center' gap={1}>
            <CircularProgress size={20} />
            <Typography color='text.secondary'>Loading…</Typography>
          </Box>
        )}

        {error && <Alert severity='error'>{error}</Alert>}

        {doc && (
          <Paper variant='outlined' sx={{ p: 3 }}>
            <MarkdownRender content={doc.content} />
            {/*
              Footer: "This text was last updated on <date> and can be
              found at <canonical>." Both fields are optional config
              (Server.AUPLastUpdated, Server.AUPCanonicalURL); we only
              render the parts we have.
            */}
            {(doc.lastUpdated || doc.canonicalUrl) && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant='body2' color='text.secondary'>
                  {doc.lastUpdated && (
                    <>This text was last updated on {doc.lastUpdated}</>
                  )}
                  {doc.lastUpdated && doc.canonicalUrl && ' and '}
                  {doc.canonicalUrl && (
                    <>
                      can be found at{' '}
                      <a
                        href={doc.canonicalUrl}
                        target='_blank'
                        rel='noreferrer'
                      >
                        {doc.canonicalUrl}
                      </a>
                    </>
                  )}
                  .
                </Typography>
              </>
            )}
          </Paper>
        )}

        {doc && authed && (
          <Box display='flex' justifyContent='flex-end'>
            <Button
              variant='contained'
              onClick={agree}
              disabled={agreeing}
            >
              {agreeing ? 'Recording…' : 'I agree'}
            </Button>
          </Box>
        )}
      </Stack>
    </Container>
  );
};

export default Page;
