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

import { Box } from '@mui/material';

import SettingHeader from '@/app/settings/components/SettingHeader';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import LogViewer from '@/app/settings/logs/components/LogViewer';

// The log viewer is accessible to either a full server admin OR a caller
// holding the dedicated pelican.log_read scope (typically granted via a
// group to a triage-only user). The backend enforces the same union in
// LogReadAuthHandler; keeping the client-side gate in sync avoids showing
// a page that will immediately 403 on every fetch.
export default function Page() {
  return (
    <AuthenticatedContent
      redirect
      allowedRoles={['admin']}
      anyScopes={['pelican.log_read']}
    >
      <Box width={'100%'}>
        <SettingHeader
          title={'Server Logs'}
          description={
            'Live view of the most recent server log lines. Older lines ' +
            'are dropped as new ones arrive.'
          }
        />
        <LogViewer />
      </Box>
    </AuthenticatedContent>
  );
}
