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

// Groups are server-wide (not origin-specific), so the route lives at
// the top level — `/groups/...` rather than under any one server type.
// We use Navigation with sharedPage=true (same chrome as /settings and
// /config, which are also server-type-agnostic) and intentionally do
// NOT gate to admins: any authenticated user can list the groups they
// belong to, and only the management actions inside are gated.
//
// We render the Settings sub-navigation here too so admins clicking
// "Groups" from the /settings/ sidebar don't lose their context.
// SubNavigation gates itself on admin — non-admin members still see
// the page without the (admin-only) sub-nav.

import { Box, Grid } from '@mui/material';
import { Main, PaddedContent } from '@/components/layout';
import { Navigation } from '@/components/layout/Navigation';
import SubNavigation from '@/app/settings/components/SubNavigation';

export const metadata = {
  title: 'Groups',
};

export default function GroupsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Navigation sharedPage={true}>
      <Main>
        <PaddedContent>
          <Grid container spacing={2}>
            <Grid size={'auto'}>
              <SubNavigation />
            </Grid>
            <Grid
              size={{
                xs: 12,
                md: 12,
                lg: 10,
                xl: 8,
              }}
            >
              <Box width={'100%'}>{children}</Box>
            </Grid>
          </Grid>
        </PaddedContent>
      </Main>
    </Navigation>
  );
}
