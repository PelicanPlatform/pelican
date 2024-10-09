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

import { merge } from 'lodash';

import _metadata from '@/public/data/parameters.json';
import { ParameterMetadataList } from '@/components/configuration';
import { Issuer } from './Issuer';

const getMetadata = async () => {
  const metadataList = _metadata as unknown as ParameterMetadataList;

  // Enumerate the fields that we want to display
  const fields = [
    "Origin.EnableOrigin",
    "Issuer.IssuerClaimValue",
    "Issuer.AuthenticationSource",
    "OIDC.ClientIDFile",
    "OIDC.ClientID",
    "OIDC.ClientSecretFile",
    "OIDC.DeviceAuthEndpoint",
    "OIDC.TokenEndpoint",
    "OIDC.UserInfoEndpoint",
    "OIDC.AuthorizationEndpoint",
    "OIDC.Issuer",
    "OIDC.ClientRedirectHostname",
    "Issuer.OIDCAuthenticationRequirements",
    "Issuer.OIDCAuthenticationUserClaim",
    "Issuer.GroupSource",
    "Issuer.OIDCGroupClaim",
    "Issuer.GroupFile",
    "Issuer.GroupRequirements",
    "Issuer.AuthorizationTemplates",
    "Issuer.UserStripDomain",
    "Issuer.TomcatLocation",
    "Issuer.ScitokensServerLocation",
    "Issuer.QDLLocation",
  ];

  // @ts-ignore
  let metadata = merge(...metadataList);

  // Pull out the Issuer Data
  const issuerMetadata: Record<string, any> = {}
  fields.forEach((field) => {
    issuerMetadata[field] = metadata[field];
  })

  return issuerMetadata;
};

const Page = async () => {
  const metadata = await getMetadata();
  return <Issuer metadata={metadata} />;
};

export default Page;
