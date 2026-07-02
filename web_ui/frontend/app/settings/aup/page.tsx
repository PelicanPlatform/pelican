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

// Admin-only AUP editor.
//
// The page shows two stacked panels: a Markdown source editor on the
// left and a live preview on the right (rendered by react-markdown via
// the existing MarkdownRender helper). Saving POSTs to PUT /aup, which
// stores the new version in aup_documents and flips it to active.
// Every save invalidates user.aup_version on every account, forcing
// re-acceptance — the warning copy on the page makes that explicit so
// admins don't trigger a federation-wide re-prompt accidentally.
//
// A version history table at the bottom lists every prior text the
// server has ever stored. We do NOT offer "rollback to this version"
// here because the SaveActiveAUP code is content-addressed: re-saving
// an old text creates the same hash again, so rollback is just "copy
// the text from the history row into the editor and save."

import React, { useContext, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Divider,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Save as SaveIcon } from '@mui/icons-material';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import MarkdownRender from '@/components/MarkdownRender';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { fetchApi, secureApiFetch } from '@/helpers/api';
import { API_V1_BASE_URL } from '@/helpers/api/constants';

// Mirrors the backend AUPDocumentResp / AUPDocument structs. Optional
// fields that don't apply (e.g. lastUpdated empty) come back undefined.
interface AUPDocumentResp {
  content: string;
  version: string;
  source: 'none' | 'default' | 'operator' | 'db';
  lastUpdated?: string;
  canonicalUrl?: string;
  editable: boolean;
}

interface AUPHistoryRow {
  id: string;
  version: string;
  content: string;
  createdBy: string;
  authMethod?: string;
  authMethodId?: string;
  lastUpdated?: string;
  isActive: boolean;
  createdAt: string;
}

const AUPSourceChip: React.FC<{ source: AUPDocumentResp['source'] }> = ({
  source,
}) => {
  switch (source) {
    case 'db':
      return (
        <Chip size='small' color='success' label='Edited via UI (active)' />
      );
    case 'operator':
      return <Chip size='small' color='info' label='From Server.AUPFile' />;
    case 'default':
      return (
        <Chip
          size='small'
          color='warning'
          variant='outlined'
          label='Pelican default — not yet customized'
        />
      );
    default:
      return null;
  }
};

const Page: React.FC = () => (
  // allowedRoles=['admin'] gates the page client-side; the backend
  // PUT /aup is also AdminAuthHandler-walled.
  <AuthenticatedContent redirect allowedRoles={['admin']}>
    <Editor />
  </AuthenticatedContent>
);

const Editor: React.FC = () => {
  const dispatch = useContext(AlertDispatchContext);

  const [doc, setDoc] = useState<AUPDocumentResp | null>(null);
  const [history, setHistory] = useState<AUPHistoryRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Editor state — initialised from the loaded doc and tracked
  // separately so the active version stays available for diffing
  // ("dirty" = pending edits) and so a save echoes back the freshly
  // resolved view without us having to re-read the editor.
  const [draft, setDraft] = useState('');
  const [draftLastUpdated, setDraftLastUpdated] = useState('');
  const [saving, setSaving] = useState(false);

  const dirty =
    doc !== null &&
    (draft !== doc.content || draftLastUpdated !== (doc.lastUpdated ?? ''));

  const reload = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`${API_V1_BASE_URL}/aup`);
      if (r.status === 404) {
        // Server.AUPFile = "none" — disabled. No editor.
        setDoc(null);
        setError(
          'AUP enforcement is disabled on this server (Server.AUPFile = "none").'
        );
        return;
      }
      if (!r.ok) {
        setError(`Failed to load AUP (HTTP ${r.status}).`);
        return;
      }
      const body = (await r.json()) as AUPDocumentResp;
      setDoc(body);
      setDraft(body.content);
      setDraftLastUpdated(body.lastUpdated ?? '');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load AUP');
    } finally {
      setLoading(false);
    }
    try {
      const r = await fetch(`${API_V1_BASE_URL}/aup/versions`);
      if (r.ok) {
        const rows = (await r.json()) as AUPHistoryRow[];
        setHistory(Array.isArray(rows) ? rows : []);
      }
    } catch {
      /* history is non-fatal */
    }
  };

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async () => {
    if (!draft.trim()) return;
    setSaving(true);
    const ok = await alertOnError(
      async () =>
        fetchApi(async () =>
          secureApiFetch(`${API_V1_BASE_URL}/aup`, {
            method: 'PUT',
            body: JSON.stringify({
              content: draft,
              lastUpdated: draftLastUpdated.trim(),
            }),
            headers: { 'Content-Type': 'application/json' },
          })
        ),
      'Failed to save AUP',
      dispatch
    );
    setSaving(false);
    if (ok) {
      const body = (await ok.json()) as AUPDocumentResp;
      setDoc(body);
      setDraft(body.content);
      setDraftLastUpdated(body.lastUpdated ?? '');
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: `AUP saved as version ${body.version}. All users must re-accept.`,
          autoHideDuration: 5000,
          alertProps: { severity: 'success' },
        },
      });
      // Refresh history list so the new row shows up.
      try {
        const r = await fetch(`${API_V1_BASE_URL}/aup/versions`);
        if (r.ok) {
          const rows = (await r.json()) as AUPHistoryRow[];
          setHistory(Array.isArray(rows) ? rows : []);
        }
      } catch {
        /* non-fatal */
      }
    }
  };

  const adoptHistory = (row: AUPHistoryRow) => {
    setDraft(row.content);
    setDraftLastUpdated(row.lastUpdated ?? '');
  };

  // Memoize so MarkdownRender doesn't re-parse on every keystroke;
  // react-markdown handles incremental updates fine but the work is
  // wasted when the editor is the only thing that changed.
  const previewContent = useMemo(() => draft, [draft]);

  return (
    <Container maxWidth='lg' sx={{ py: 3 }}>
      <Stack spacing={3}>
        <Box>
          <Typography variant='h4' gutterBottom>
            Acceptable Use Policy
          </Typography>
          <Typography variant='body2' color='text.secondary'>
            Edit the Markdown source on the left; the rendered preview on the
            right updates as you type. Saving installs the new text as the
            active policy and forces every user on the server to re-accept on
            their next visit.
          </Typography>
        </Box>

        {loading && (
          <Box display='flex' alignItems='center' gap={1}>
            <CircularProgress size={20} />
            <Typography color='text.secondary'>Loading…</Typography>
          </Box>
        )}

        {error && <Alert severity='error'>{error}</Alert>}

        {doc && (
          <>
            <Stack
              direction='row'
              spacing={1}
              alignItems='center'
              flexWrap='wrap'
            >
              <AUPSourceChip source={doc.source} />
              <Chip
                size='small'
                variant='outlined'
                sx={{ fontFamily: 'monospace' }}
                label={`Active version: ${doc.version}`}
              />
              {doc.source !== 'db' && (
                <Alert severity='info' sx={{ flexBasis: '100%' }}>
                  The active policy is currently the{' '}
                  {doc.source === 'default'
                    ? 'Pelican-shipped default'
                    : 'file at Server.AUPFile'}
                  . Saving here will store an operator-edited copy in the
                  database; that copy will then take precedence over the
                  file/default until removed.
                </Alert>
              )}
            </Stack>

            <Box
              display='grid'
              gap={2}
              sx={{
                gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' },
              }}
            >
              <Paper variant='outlined' sx={{ p: 2 }}>
                <Typography variant='subtitle2' gutterBottom>
                  Markdown source
                </Typography>
                <TextField
                  multiline
                  minRows={20}
                  maxRows={40}
                  fullWidth
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  disabled={saving}
                  slotProps={{
                    input: {
                      style: {
                        fontFamily:
                          'ui-monospace, SFMono-Regular, Menlo, monospace',
                        fontSize: '0.85rem',
                      },
                    },
                  }}
                />
              </Paper>

              <Paper variant='outlined' sx={{ p: 3, overflow: 'auto' }}>
                <Typography variant='subtitle2' gutterBottom>
                  Preview
                </Typography>
                <MarkdownRender content={previewContent} />
              </Paper>
            </Box>

            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={2}
              alignItems={{ sm: 'center' }}
            >
              <TextField
                label='Last updated (footer)'
                size='small'
                value={draftLastUpdated}
                onChange={(e) => setDraftLastUpdated(e.target.value)}
                disabled={saving}
                placeholder='e.g. 3 April 2026'
                helperText='Optional. Rendered in the AUP footer.'
                sx={{ minWidth: 280 }}
              />
              <Box flexGrow={1} />
              <Button
                variant='contained'
                startIcon={<SaveIcon />}
                onClick={submit}
                disabled={!dirty || saving || !draft.trim()}
              >
                {saving ? 'Saving…' : 'Save as new active version'}
              </Button>
            </Stack>

            <Divider />

            <Box>
              <Typography variant='h5' gutterBottom>
                Version history
              </Typography>
              {history.length === 0 ? (
                <Typography color='text.secondary'>
                  No edits yet — the active version above is the current
                  source-of-truth.
                </Typography>
              ) : (
                <Stack spacing={1.5}>
                  {history.map((row) => (
                    <Paper key={row.id} variant='outlined' sx={{ p: 1.5 }}>
                      <Stack
                        direction='row'
                        spacing={1}
                        alignItems='center'
                        flexWrap='wrap'
                      >
                        <Chip
                          size='small'
                          variant='outlined'
                          sx={{ fontFamily: 'monospace' }}
                          label={row.version}
                        />
                        {row.isActive && (
                          <Chip size='small' color='success' label='active' />
                        )}
                        <Typography variant='body2' color='text.secondary'>
                          Saved {new Date(row.createdAt).toLocaleString()} by{' '}
                          {row.createdBy}
                        </Typography>
                        <Box flexGrow={1} />
                        <Button
                          size='small'
                          onClick={() => adoptHistory(row)}
                          disabled={saving}
                        >
                          Load into editor
                        </Button>
                      </Stack>
                    </Paper>
                  ))}
                </Stack>
              )}
            </Box>
          </>
        )}
      </Stack>
    </Container>
  );
};

export default Page;
