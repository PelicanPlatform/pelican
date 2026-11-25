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

import { fetchApi } from '@/helpers/api';
import { API_V1_BASE_URL } from '../constants';
import { ApiService } from '../types';
import { OriginExportPrefixes } from './types';

type OriginExportApiService = ApiService & {
  getPrefixes: () => Promise<OriginExportPrefixes>;
};

const OriginExportService = {
  id: 'OriginExport',
  // Any logged-in user may call this; the full /origin_ui/exports
  // response is admin-only because it carries storage details and
  // registry edit tokens.
  getPrefixes: async (): Promise<OriginExportPrefixes> => {
    const response = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/origin_ui/exports/prefixes`)
    );
    return await response.json();
  },
} as const satisfies OriginExportApiService;

export default OriginExportService;
