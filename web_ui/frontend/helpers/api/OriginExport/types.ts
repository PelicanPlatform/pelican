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

// Types for GET /api/v1.0/origin_ui/exports/prefixes (handleExportPrefixes
// in origin/exports.go): the slice of the origin's exports that any
// logged-in user may read. The admin-only /origin_ui/exports response is
// typed separately in components/DataExportTable.tsx.

export interface PublicOriginExport {
  federationPrefix: string;
  /** Whether the export can be read without a token. */
  publicRead: boolean;
}

export interface OriginExportPrefixes {
  /** FederationPrefix of each export, in declaration order. */
  prefixes: string[];
  exports: PublicOriginExport[];
  /**
   * The origin's data endpoint (Origin.Url). It is on a different port than
   * the web UI, so requests to it are cross-origin and rely on CORS there.
   */
  originUrl: string;
}
