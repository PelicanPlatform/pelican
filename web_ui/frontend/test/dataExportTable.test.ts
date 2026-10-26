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

import { exportCardKind } from '@/helpers/exports';

describe('Data Exports card selection', () => {
  // Every value of server_structs.OriginStorageType on the Go side. Keep in
  // step with ParseOriginStorageType: a type missing here is a type the
  // Data Exports page may be rendering as nothing.
  const knownStorageTypes = [
    'posix',
    'posixv2',
    'ssh',
    's3',
    's3v2',
    'https',
    'httpsv2',
    'globus',
    'globusv2',
    'pstore',
    'xroot',
  ];

  test('every known storage type maps to a card', () => {
    for (const storageType of knownStorageTypes) {
      expect(exportCardKind(storageType)).toBeDefined();
    }
  });

  test('native v2 backends share the card of the backend they mirror', () => {
    // posixv2 is the regression from PelicanPlatform/pelican#3830: the
    // registration status, and with it the "Complete Registration" button,
    // never rendered because only 'posix' had a case.
    expect(exportCardKind('posixv2')).toEqual('posix');
    expect(exportCardKind('s3v2')).toEqual('s3');
    expect(exportCardKind('globusv2')).toEqual('globus');
  });

  test('backends with a storage prefix use the POSIX card', () => {
    for (const storageType of ['xroot', 'ssh', 'https', 'httpsv2', 'pstore']) {
      expect(exportCardKind(storageType)).toEqual('posix');
    }
  });

  test('an unknown storage type falls back to the generic card', () => {
    expect(exportCardKind('some-future-backend')).toEqual('generic');
    expect(exportCardKind('')).toEqual('generic');
  });
});
