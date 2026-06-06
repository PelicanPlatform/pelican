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
  Chip,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { Cancel, Refresh } from '@mui/icons-material';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { getErrorMessage } from '@/helpers/util';

interface TransferJob {
  job_id: string;
  status: string;
  created_at: string;
  completed_at?: string;
  error?: string;
}

interface TransferJobListResponse {
  jobs: TransferJob[];
  total: number;
  limit: number;
  offset: number;
}

const statusColor = (
  status: string
): 'default' | 'primary' | 'success' | 'error' | 'warning' => {
  switch (status) {
    case 'pending':
    case 'running':
      return 'primary';
    case 'completed':
      return 'success';
    case 'failed':
    case 'cancelled':
      return 'error';
    default:
      return 'default';
  }
};

export default function TransferJobsPage() {
  const [jobs, setJobs] = useState<TransferJob[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchJobs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1.0/transfer/jobs?limit=50');
      if (!response.ok) {
        const errMsg = await getErrorMessage(response);
        setError(errMsg);
        return;
      }
      const data: TransferJobListResponse = await response.json();
      setJobs(data.jobs || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch jobs');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  const handleCancel = async (jobId: string) => {
    try {
      const response = await fetch(`/api/v1.0/transfer/jobs/${jobId}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        const errMsg = await getErrorMessage(response);
        setError(errMsg);
        return;
      }
      fetchJobs();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to cancel job');
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
          <Typography variant='h4'>Transfer Jobs</Typography>
          <Button
            startIcon={<Refresh />}
            onClick={fetchJobs}
            variant='outlined'
          >
            Refresh
          </Button>
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
                <TableCell>Job ID</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Completed</TableCell>
                <TableCell>Error</TableCell>
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
              ) : jobs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align='center'>
                    No transfer jobs found.
                  </TableCell>
                </TableRow>
              ) : (
                jobs.map((job) => (
                  <TableRow key={job.job_id}>
                    <TableCell>
                      <Typography variant='body2' fontFamily='monospace'>
                        {job.job_id.substring(0, 8)}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={job.status}
                        color={statusColor(job.status)}
                        size='small'
                      />
                    </TableCell>
                    <TableCell>
                      {new Date(job.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      {job.completed_at
                        ? new Date(job.completed_at).toLocaleString()
                        : '-'}
                    </TableCell>
                    <TableCell>
                      {job.error ? (
                        <Tooltip title={job.error}>
                          <Typography
                            variant='body2'
                            color='error'
                            noWrap
                            sx={{ maxWidth: 200 }}
                          >
                            {job.error}
                          </Typography>
                        </Tooltip>
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    <TableCell>
                      {(job.status === 'pending' ||
                        job.status === 'running') && (
                        <Tooltip title='Cancel job'>
                          <IconButton
                            size='small'
                            color='error'
                            onClick={() => handleCancel(job.job_id)}
                          >
                            <Cancel />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    </AuthenticatedContent>
  );
}
