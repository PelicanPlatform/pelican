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
import useSWR from 'swr';
import { Alert, Box, Skeleton, Typography } from '@mui/material';
import { OriginClient } from '@pelicanplatform/components';
import type { OriginNamespaceConfig } from '@pelicanplatform/hooks';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import PelicanClientRegistrar from '@/components/PelicanClientRegistrar';
import { getExportData } from '@/components/DataExportTable';
import { getConfig } from '@/helpers/api';
import { getObjectValue } from '@/helpers/util';
import { Config } from '@/components/configuration';

interface OriginClientConfig {
  /**
   * The Origin's data (XRootD) endpoint -- where OriginClient sends
   * PROPFIND/GET. This is Origin.Url (a different port than the web UI), so
   * it is cross-origin to the page and relies on CORS on the data endpoint.
   */
  originBaseUrl: string;
  /**
   * Whether the origin runs its *embedded* PKCE issuer. The object browser
   * authenticates via that browser flow, which does not exist in OA4MP mode
   * (or when the issuer is disabled), so the browser can't log in there.
   */
  embeddedIssuer: boolean;
}

/** Reads the origin client's config from GET /config in a single fetch. */
const getOriginClientConfig = async (): Promise<OriginClientConfig> => {
  const response = await getConfig();
  const config = (await response.json()) as Config;
  const originBaseUrl =
    getObjectValue<string>(config, ['Origin', 'Url']) || window.location.origin;
  const enableIssuer = getObjectValue<boolean>(config, [
    'Origin',
    'EnableIssuer',
  ]);
  // Origin.IssuerMode defaults to "embedded" when unset (see the
  // "embedded", "" switch in launchers/origin_serve.go); only "oa4mp" opts
  // out of the embedded issuer.
  const issuerMode = getObjectValue<string>(config, ['Origin', 'IssuerMode']);
  const embeddedIssuer = !!enableIssuer && issuerMode !== 'oa4mp';
  return { originBaseUrl, embeddedIssuer };
};

export default function Page() {
  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin']}>
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
 * Loads the Origin's exports and data endpoint, then mounts the self-contained
 * OriginClient. OriginClient brings its own provider, namespace selector, and
 * file browser, and keeps every request local to this Origin (no director).
 *
 * Namespace mapping (per the OriginClient guidance):
 *   prefix       <- export.federationPrefix
 *   issuer       <- export.issuerUrls[0]   (falls back to this Origin's embedded
 *                   issuer so silent login stays same-origin with the UI)
 *   requireToken <- !export.capabilities.PublicRead
 */
const OriginObjectBrowser = () => {
  const { data: exportData } = useSWR('getDataExport', getExportData);
  const { data: originClientConfig } = useSWR(
    'getOriginClientConfig',
    getOriginClientConfig
  );

  const namespaces: OriginNamespaceConfig[] | undefined = useMemo(() => {
    if (!exportData) {
      return undefined;
    }
    // exports is a union of per-type arrays; we only need fields shared by all.
    const entries = exportData.exports as {
      federationPrefix: string;
      issuerUrls?: string[];
      capabilities?: { PublicRead?: boolean };
    }[];

    const seen = new Set<string>();
    const result: OriginNamespaceConfig[] = [];
    entries.forEach((e) => {
      if (!e.federationPrefix || seen.has(e.federationPrefix)) {
        return;
      }
      seen.add(e.federationPrefix);
      result.push({
        prefix: e.federationPrefix,
        issuer:
          e.issuerUrls?.[0] ||
          `${window.location.origin}/api/v1.0/issuer/ns${e.federationPrefix}`,
        requireToken: !e.capabilities?.PublicRead,
      });
    });
    return result.sort((a, b) => a.prefix.localeCompare(b.prefix));
  }, [exportData]);

  if (namespaces === undefined || originClientConfig === undefined) {
    return <Skeleton variant={'rectangular'} height={400} width={'100%'} />;
  }

  // The object browser logs in through the origin's embedded PKCE issuer; if
  // the origin uses OA4MP (or has the issuer disabled) that flow is
  // unavailable, so surface why the browser isn't shown rather than mounting
  // a client that can never authenticate.
  if (!originClientConfig.embeddedIssuer) {
    return (
      <Alert severity={'info'}>
        The object browser requires the origin&apos;s embedded token issuer,
        which is not enabled on this server (it is configured to use OA4MP, or
        the issuer is disabled).
      </Alert>
    );
  }

  if (namespaces.length === 0) {
    return (
      <Alert severity={'info'}>This origin has no exports to browse.</Alert>
    );
  }

  return (
    <OriginClient
      originBaseUrl={originClientConfig.originBaseUrl}
      namespaces={namespaces}
    />
  );
};
