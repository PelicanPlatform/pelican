'use client';

import Link from 'next/link';
import { green, grey, orange, red } from '@mui/material/colors';
import {
  Typography,
  Box,
  BoxProps,
  Button,
  Grid,
  Tooltip,
  Pagination,
  Paper,
  Alert,
  IconButton, LinearProgress,
} from '@mui/material';
import React, { ReactElement, useEffect, useMemo, useState } from 'react';
import { Skeleton } from '@mui/material';

import { Edit, Settings, Check, Clear } from '@mui/icons-material';
import useSWR from 'swr';
import { getErrorMessage } from '@/helpers/util';
import { Capabilities } from '@/types';
import { CapabilitiesDisplay } from '@/components';
import CircularProgress from '@mui/material/CircularProgress';
import { useSearchParams } from 'next/navigation';

type RegistrationStatus =
  | 'Not Supported'
  | 'Completed'
  | 'Incomplete'
  | 'Registration Error';

type ExportResCommon = {
  status: RegistrationStatus;
  statusDescription: string;
  editUrl: string;
};

type ExportRes = ExportResCommon &
  (
    | { type: 's3'; exports: S3ExportEntry[] }
    | { type: 'posix'; exports: PosixExportEntry[] }
    | { type: 'globus'; exports: GlobusExportEntry[] }
  );

interface ExportEntry {
  status: RegistrationStatus;
  statusDescription: string;
  editUrl: string;
  federationPrefix: string;
  capabilities: Capabilities;
}

interface GlobusExportEntry extends ExportEntry {
  globusCollectionID: string;
  globusCollectionName: string;
}

interface S3ExportEntry extends ExportEntry {
  s3AccessKeyfile: string;
  s3SecretKeyfile: string;
  s3Bucket: string;
}

interface PosixExportEntry extends ExportEntry {
  storagePrefix: string;
  sentinelLocation: string;
}

export const DataExportStatus = ({
  status,
  statusDescription,
  editUrl,
}: {
  status: RegistrationStatus;
  statusDescription: string;
  editUrl: string;
}) => {
  switch (status) {
    case 'Completed':
      return null;
    case 'Incomplete':
      return (
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            backgroundColor: red[50],
            p: 1,
            borderRadius: 1,
          }}
        >
          <Box pr={1} my={'auto'}>
            <Typography variant={'body2'}>{statusDescription}</Typography>
          </Box>
          <Box>
            <Button
              variant={'contained'}
              color={'warning'}
              href={editUrl}
              endIcon={<Edit />}
            >
              Complete Registration
            </Button>
          </Box>
        </Box>
      );
    default:
      return (
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            backgroundColor: red[50],
            p: 1,
            borderRadius: 1,
          }}
        >
          <Box pr={1} my={'auto'}>
            <Typography variant={'body2'}>
              {status}:{statusDescription}
            </Typography>
          </Box>
        </Box>
      );
  }
};

export const ValueLabel = ({
  value,
  label,
}: {
  value: string;
  label: string;
}) => {
  if (!value) {
    return null;
  }

  return (
    <Box display={'flex'} flexDirection={'column'}>
      <Typography
        sx={{
          backgroundColor: grey[200],
          mr: 'auto',
          px: 1,
          borderRadius: 0.5,
        }}
        variant={'caption'}
      >
        {label}
      </Typography>
      <Typography
        pl={0.5}
        pt={0.6}
        pb={0.8}
        variant={'h6'}
        sx={{ wordBreak: 'break-all' }}
      >
        {value}
      </Typography>
    </Box>
  );
};

export const PosixDataExportCard = ({ entry }: { entry: PosixExportEntry }) => {
  return (
    <Paper elevation={1}>
      {entry.status != 'Completed' && <DataExportStatus {...entry} />}
      <Grid container p={1}>
        <Grid item xs={9}>
          <ValueLabel
            value={entry.federationPrefix}
            label={'Federation Prefix'}
          />
          <ValueLabel value={entry.storagePrefix} label={'Storage Prefix'} />
          <ValueLabel
            value={entry.sentinelLocation}
            label={'Sentinel Location'}
          />
        </Grid>
        <Grid item xs={3}>
          <CapabilitiesDisplay {...entry} />
        </Grid>
      </Grid>
    </Paper>
  );
};

export const S3DataExportCard = ({ entry }: { entry: S3ExportEntry }) => {
  return (
    <Paper elevation={1}>
      {entry.status != 'Completed' && <DataExportStatus {...entry} />}
      <Grid container pt={1}>
        <Grid item xs={9}>
          <ValueLabel
            value={entry.federationPrefix}
            label={'Federation Prefix'}
          />
          <ValueLabel value={entry.s3Bucket} label={'S3 Bucket'} />
        </Grid>
        <Grid item xs={3}>
          <CapabilitiesDisplay {...entry} />
        </Grid>
      </Grid>
    </Paper>
  );
};

export const GlobusDataExportCard = ({
  entry,
}: {
  entry: GlobusExportEntry;
}) => {
  return (
    <Paper elevation={1}>
      {entry.status != 'Completed' && <DataExportStatus {...entry} />}
      <Grid container pt={1}>
        <Grid item xs={9}>
          <ValueLabel
            value={entry.federationPrefix}
            label={'Federation Prefix'}
          />
          <ValueLabel
            value={entry.globusCollectionName || ''}
            label={'Globus Collection Name'}
          />
          <ValueLabel
            value={entry.globusCollectionID}
            label={'Globus Collection ID'}
          />
        </Grid>
        <Grid item xs={3}>
          <Box
            width={'100%'}
            display={'flex'}
            justifyContent={'end'}
            marginBottom={'0.5em'}
            marginRight={'0.5em'}
          >
            <Tooltip title='Configure Globus export'>
              <Link href={'/origin/globus/'}>
                <IconButton aria-label='Configure Globus Export'>
                  <Settings />
                </IconButton>
              </Link>
            </Tooltip>
          </Box>
          <CapabilitiesDisplay {...entry} />
        </Grid>
      </Grid>
    </Paper>
  );
};

export const Paginator = ({
  data,
  page,
  setPage,
  pageSize,
}: {
  data: any[];
  page: number;
  pageSize: number;
  setPage: (p: number) => void;
}) => {
  if (data.length <= pageSize) {
    return null;
  }

  return (
    <Box display={'flex'} justifyContent={'center'} pb={1}>
      <Pagination
        count={Math.round(data.length / pageSize)}
        page={page}
        onChange={(e, p) => setPage(p)}
      ></Pagination>
    </Box>
  );
};

export const RecordTable = ({ data }: { data: ExportRes }): ReactElement => {
  const [page, setPage] = useState<number>(1);

  // Get the array values indicated by the current page and a pageSize of 2
  const entryPage: ExportEntry[] = useMemo(() => {
    const start = (page - 1) * 2;
    const end = start + 2;
    return Object.values(data.exports).slice(start, end);
  }, [page, data]);

  switch (data.type) {
    case 's3':
      return (
        <>
          {entryPage.map((entry, index) => (
            <Box key={entry.federationPrefix} pb={1}>
              <S3DataExportCard entry={entry as S3ExportEntry} />
            </Box>
          ))}
          <Paginator
            data={data.exports}
            page={page}
            pageSize={2}
            setPage={setPage}
          />
        </>
      );
    case 'posix':
      return (
        <>
          {entryPage.map((entry, index) => (
            <Box key={entry.federationPrefix} pb={1}>
              <PosixDataExportCard entry={entry as PosixExportEntry} />
            </Box>
          ))}
          <Paginator
            data={data.exports}
            page={page}
            pageSize={2}
            setPage={setPage}
          />
        </>
      );
    case 'globus':
      return (
        <>
          {entryPage.map((entry, index) => (
            <Box key={entry.federationPrefix} pb={1}>
              <GlobusDataExportCard entry={entry as GlobusExportEntry} />
            </Box>
          ))}
          <Paginator
            data={data.exports}
            page={page}
            pageSize={2}
            setPage={setPage}
          />
        </>
      );
  }
};

export const getExportData = async (): Promise<ExportRes> => {
  let response = await fetch('/api/v1.0/origin_ui/exports');
  if (response.ok) {
    const responseData = await response.json();
    return responseData;
  } else {
    throw new Error(await getErrorMessage(response));
  }
};

const generateEditUrl = (editUrl: string, fromUrl: string) => {
  try {
    let updatedFromUrl = new URL(fromUrl)
    if(!('from_registry' in updatedFromUrl.searchParams)) {
      updatedFromUrl.searchParams.append('from_registry', 'true')
    }
    const url = new URL(editUrl);
    url.searchParams.append('fromUrl', updatedFromUrl.toString());
    return url.toString();
  } catch (e) {
    console.error('Failed to generate editUrl', e);
    return editUrl;
  }
}

export const DataExportTable = ({ boxProps }: { boxProps?: BoxProps }) => {
  const [pending, setPending] = useState<boolean>(false);
  const [ fromUrl, setFromUrl ] = useState<string | undefined>(undefined);
  const { data, mutate } = useSWR('getDataExport', getExportData, {
    refreshInterval: 10000
  });

  useEffect(() => {
    setFromUrl(window.location.href);
    setPending(true);
    setTimeout(() => {
      mutate()
      setPending(false);
    }, 5000);
  }, []);

  const searchParams = useSearchParams()
  const from_registry = searchParams.get('from_registry') == 'true'

  const dataEnhanced = useMemo(() => {

    // If no from URL return current data
    if (!fromUrl) {
      return data;
    }

    // If data is not available, return null
    if (!data) {
      return undefined;
    }

    let dataEnhanced = structuredClone(data)
    dataEnhanced.editUrl = generateEditUrl(dataEnhanced.editUrl, fromUrl);
    dataEnhanced.exports.map((val) => {
      val.editUrl = generateEditUrl(val.editUrl, fromUrl);
    });

    return dataEnhanced;

  }, [data, fromUrl])

  return (
    <Box {...boxProps}>
      {from_registry && pending &&
        <Box display={"flex"} flexDirection={"column"}>
          <LinearProgress sx={{mb:1, w: "100%"}} />
          <Typography variant={'subtitle2'} color={grey[400]} mx={"auto"}>Checking Registry for Updates</Typography>
        </Box>
      }
      <Typography pb={1} variant={'h5'} component={'h3'}>
        Origin
      </Typography>
      {dataEnhanced &&
      dataEnhanced.status &&
      dataEnhanced.status != 'Completed' ? (
        <DataExportStatus
          status={dataEnhanced.status}
          statusDescription={dataEnhanced.statusDescription}
          editUrl={dataEnhanced.editUrl}
        />
      ) : (
        <Alert severity='success'>Registration Completed</Alert>
      )}

      <Typography pt={2} pb={1} variant={'h5'} component={'h3'}>
        Namespaces
      </Typography>
      {dataEnhanced ? (
        <RecordTable data={dataEnhanced} />
      ) : (
        <Skeleton variant={'rectangular'} height={200} width={'100%'} />
      )}
    </Box>
  );
};
