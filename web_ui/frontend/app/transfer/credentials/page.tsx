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

'use client';

import { useEffect, useState, useCallback } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { Add, Delete, Refresh } from '@mui/icons-material';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { getErrorMessage } from '@/helpers/util';

interface Credential {
  id: string;
  name: string;
  credential_type: string;
  token_issuer?: string;
  token_expiry?: string;
  last_used_at?: string;
  created_at: string;
  updated_at: string;
}

export default function TransferCredentialsPage() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newToken, setNewToken] = useState('');
  const [newIssuer, setNewIssuer] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const fetchCredentials = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1.0/transfer/credentials');
      if (!response.ok) {
        const errMsg = await getErrorMessage(response);
        setError(errMsg);
        return;
      }
      const data: Credential[] = await response.json();
      setCredentials(data || []);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Failed to fetch credentials'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  const handleAdd = async () => {
    if (!newName || !newToken) return;
    setSubmitting(true);
    setError(null);
    try {
      const body: Record<string, string> = {
        name: newName,
        access_token: newToken,
      };
      if (newIssuer) {
        body.token_issuer = newIssuer;
      }
      const response = await fetch('/api/v1.0/transfer/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const errMsg = await getErrorMessage(response);
        setError(errMsg);
        return;
      }
      setDialogOpen(false);
      setNewName('');
      setNewToken('');
      setNewIssuer('');
      fetchCredentials();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add credential');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/v1.0/transfer/credentials/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        const errMsg = await getErrorMessage(response);
        setError(errMsg);
        return;
      }
      fetchCredentials();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Failed to delete credential'
      );
    }
  };

  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin']}>
      <Box width={'100%'}>
        <Box
          display='flex'
          justifyContent='space-between'
          alignItems='center'
          mb={2}
        >
          <Typography variant='h4'>Transfer Credentials</Typography>
          <Box>
            <Button
              startIcon={<Refresh />}
              onClick={fetchCredentials}
              variant='outlined'
              sx={{ mr: 1 }}
            >
              Refresh
            </Button>
            <Button
              startIcon={<Add />}
              onClick={() => setDialogOpen(true)}
              variant='contained'
            >
              Add Credential
            </Button>
          </Box>
        </Box>

        {error && (
          <Alert severity='error' sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Issuer</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Last Used</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} align='center'>
                    Loading...
                  </TableCell>
                </TableRow>
              ) : credentials.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align='center'>
                    No credentials found.
                  </TableCell>
                </TableRow>
              ) : (
                credentials.map((cred) => (
                  <TableRow key={cred.id}>
                    <TableCell>{cred.name}</TableCell>
                    <TableCell>{cred.credential_type}</TableCell>
                    <TableCell>{cred.token_issuer || '-'}</TableCell>
                    <TableCell>
                      {new Date(cred.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      {cred.last_used_at
                        ? new Date(cred.last_used_at).toLocaleString()
                        : '-'}
                    </TableCell>
                    <TableCell>
                      <Tooltip title='Delete credential'>
                        <IconButton
                          size='small'
                          color='error'
                          onClick={() => handleDelete(cred.id)}
                        >
                          <Delete />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <Dialog
          open={dialogOpen}
          onClose={() => setDialogOpen(false)}
          maxWidth='sm'
          fullWidth
        >
          <DialogTitle>Add Credential</DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              margin='dense'
              label='Name'
              fullWidth
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <TextField
              margin='dense'
              label='Access Token'
              fullWidth
              multiline
              rows={3}
              value={newToken}
              onChange={(e) => setNewToken(e.target.value)}
            />
            <TextField
              margin='dense'
              label='Token Issuer (optional)'
              fullWidth
              value={newIssuer}
              onChange={(e) => setNewIssuer(e.target.value)}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleAdd}
              variant='contained'
              disabled={!newName || !newToken || submitting}
            >
              {submitting ? 'Adding...' : 'Add'}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </AuthenticatedContent>
  );
}
