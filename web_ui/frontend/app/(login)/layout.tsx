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
  title: 'Login',
};

/**
 * Shell for the pages a caller reaches before (or instead of) the admin UI:
 * login, first-run activation and password setup, device authorization, and
 * the 403 landing. There is no rail here, so the content is centred in the
 * viewport rather than offset to clear one -- the previous layout reused
 * `Main`, which reserves the rail's width and pushed these pages to the right
 * on desktop for a sidebar that never rendered.
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        bgcolor: 'grey.50',
        // A soft wash of the brand blue behind the card, fading to the page
        // colour well before the fold, so the panel reads as the one object
        // on the page without the page itself going flat.
        backgroundImage:
          'radial-gradient(ellipse 80% 50% at 50% -10%, rgba(8, 133, 255, 0.14), rgba(8, 133, 255, 0))',
      }}
    >
      <Header text={'Pelican Platform'} />
      <Box
        component={'main'}
        sx={{
          flexGrow: 1,
          display: 'flex',
          alignItems: { xs: 'flex-start', sm: 'center' },
          justifyContent: 'center',
          px: 2,
          py: { xs: 4, sm: 8 },
        }}
      >
        {children}
      </Box>
    </Box>
  );
}
