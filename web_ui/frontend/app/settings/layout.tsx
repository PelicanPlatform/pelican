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

import { Box, Grid } from '@mui/material';
import { Main } from '@/components/layout/Main';
import { PaddedContent } from '@/components/layout';
import { Navigation } from '@/components/layout/Navigation';
import SubNavigation from '@/app/settings/components/SubNavigation';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

export const metadata = {
  title: 'Settings',
  description: 'Server Settings',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Navigation sharedPage={true}>
      <Main>
        <AuthenticatedContent
          redirect
          allowedRoles={['admin']}
          boxProps={{ width: '100%' }}
        >
          <PaddedContent>
            <Grid container spacing={2}>
              <Grid
                size={{
                  xs: 12,
                  md: 2,
                }}
              >
                <SubNavigation />
              </Grid>
              <Grid
                size={{
                  xs: 12,
                  md: 8,
                  lg: 6,
                }}
              >
                <Box width={'100%'}>{children}</Box>
              </Grid>
            </Grid>
          </PaddedContent>
        </AuthenticatedContent>
      </Main>
    </Navigation>
  );
}
