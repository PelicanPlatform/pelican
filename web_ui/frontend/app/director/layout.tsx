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

import { Box } from '@mui/material';
import { ButtonLink, Sidebar } from '@/components/layout/Sidebar';
import BuildIcon from '@mui/icons-material/Build';
import Main from '@/components/layout/Main';
import { Block, Dashboard, Equalizer, MapOutlined } from '@mui/icons-material';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

export const metadata = {
  title: 'Pelican Director',
  description: 'Software designed to make data distribution easy',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Box display={'flex'} flexDirection={'row'}>
      <Sidebar>
        <ButtonLink title={'Dashboard'} href={'/director/'}>
          <Dashboard />
        </ButtonLink>
        <ButtonLink title={'Map'} href={'/director/map/'}>
          <MapOutlined />
        </ButtonLink>
        <AuthenticatedContent allowedRoles={['admin']}>
          <ButtonLink title={'Metrics'} href={'/director/metrics/'}>
            <Equalizer />
          </ButtonLink>
        </AuthenticatedContent>
        <AuthenticatedContent allowedRoles={['admin']}>
          <ButtonLink title={'Config'} href={'/config/'}>
            <BuildIcon />
          </ButtonLink>
        </AuthenticatedContent>
      </Sidebar>
      <Main>{children}</Main>
    </Box>
  );
}
