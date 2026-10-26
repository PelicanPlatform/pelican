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

// Which card the Data Exports page renders for an export of the given
// storage type (Origin.StorageType verbatim, i.e. any
// server_structs.OriginStorageType on the Go side).
//
// Every backend that has a storage prefix shares the POSIX card; the native
// "v2" backends share the card of the XRootD backend they mirror; anything
// else falls back to the generic card, which shows the fields every export
// has. Kept as a pure function in its own module so the mapping can be
// unit-tested: an unknown type used to hit a switch with no default and the
// whole table silently rendered nothing (PelicanPlatform/pelican#3830).
export type ExportCardKind = 'posix' | 's3' | 'globus' | 'generic';

export const exportCardKind = (storageType: string): ExportCardKind => {
  switch (storageType) {
    case 's3':
    case 's3v2':
      return 's3';
    case 'globus':
    case 'globusv2':
      return 'globus';
    case 'posix':
    case 'posixv2':
    case 'xroot':
    case 'ssh':
    case 'https':
    case 'httpsv2':
    case 'pstore':
      return 'posix';
    default:
      return 'generic';
  }
};
