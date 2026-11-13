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

import { useMemo } from 'react';
import { Alert, Box, Skeleton, Typography } from '@mui/material';
import { OriginClient } from '@pelicanplatform/components';
import type { OriginNamespaceConfig } from '@pelicanplatform/hooks';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import PelicanClientRegistrar from '@/components/PelicanClientRegistrar';
import { OriginExportService } from '@/helpers/api/OriginExport';
import useServiceSWR from '@/hooks/useServiceSWR';
import { errorToString } from '@/helpers/util';

export default function Page() {
  return (
    <AuthenticatedContent redirect={true}>
      <PelicanClientRegistrar />
      <Box width={'100%'}>
        <Typography variant={'h4'} mb={2}>
          Object Browser
        </Typography>
        <OriginObjectBrowser />
      </Box>
    </AuthenticatedContent>
  );
}

/**
 * Loads the Origin's exports and data endpoint (from the non-admin
 * /origin_ui/exports/prefixes endpoint), then mounts the self-contained
 * OriginClient. OriginClient brings its own provider, namespace selector, and
 * file browser, and keeps every request local to this Origin (no director).
 *
 * Namespace mapping (per the OriginClient guidance):
 *   prefix       <- export.federationPrefix
 *   issuer       <- this Origin's embedded per-namespace issuer, so silent
 *                   login stays same-origin with the UI
 *   requireToken <- !export.publicRead
 */
const OriginObjectBrowser = () => {
  const { data, error } = useServiceSWR(
    'Failed to load origin exports',
    OriginExportService,
    'getPrefixes',
    []
  );

  const namespaces: OriginNamespaceConfig[] | undefined = useMemo(() => {
    if (!data) {
      return undefined;
    }
    const seen = new Set<string>();
    const result: OriginNamespaceConfig[] = [];
    data.exports.forEach((e) => {
      if (!e.federationPrefix || seen.has(e.federationPrefix)) {
        return;
      }
      seen.add(e.federationPrefix);
      result.push({
        prefix: e.federationPrefix,
        issuer: `${window.location.origin}/api/v1.0/issuer/ns${e.federationPrefix}`,
        requireToken: !e.publicRead,
      });
    });
    return result.sort((a, b) => a.prefix.localeCompare(b.prefix));
  }, [data]);

  if (error) {
    return <Alert severity={'error'}>{errorToString(error)}</Alert>;
  }

  if (namespaces === undefined || data === undefined) {
    return <Skeleton variant={'rectangular'} height={400} width={'100%'} />;
  }

  if (namespaces.length === 0) {
    return (
      <Alert severity={'info'}>This origin has no exports to browse.</Alert>
    );
  }

  return (
    <OriginClient
      originBaseUrl={data.originUrl || window.location.origin}
      namespaces={namespaces}
    />
  );
};
