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

import { Box } from '@mui/material';

import { Header } from '@/components/layout/Header';

export const metadata = {
  title: 'Invite',
};

// Bare layout (no admin sidebar, no enabled-services list) so an invite
// recipient can reach this page without first knowing their way around the
// admin UI.
export default function InviteLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Header text='Pelican Platform' />
      <Box component='main' pt='75px' display='flex' minHeight='100vh'>
        {children}
      </Box>
    </>
  );
}
