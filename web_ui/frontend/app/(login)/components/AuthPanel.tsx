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

import { ReactNode } from 'react';
import Image from 'next/image';
import { Paper, Stack, Typography } from '@mui/material';

import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';

type AuthPanelProps = {
  title: string;
  /** One line under the title saying what the page is for. */
  description?: ReactNode;
  /** Hide the logo when the page above already shows it prominently. */
  showLogo?: boolean;
  maxWidth?: number;
  children: ReactNode;
};

/**
 * The single card every pre-login page is built from: logo, a heading, one
 * line of explanation, then the page's own controls.
 *
 * Login, activation, password setup, device authorization and the 403 page
 * each used to lay out their own centred column with its own top margin and
 * heading size, so no two of them lined up. Sharing the card means a change
 * to the look of one is a change to all of them.
 */
export const AuthPanel = ({
  title,
  description,
  showLogo = true,
  maxWidth = 440,
  children,
}: AuthPanelProps) => (
  <Paper
    variant={'outlined'}
    sx={{
      width: '100%',
      maxWidth,
      p: { xs: 3, sm: 4 },
      borderRadius: 3,
    }}
  >
    <Stack spacing={3}>
      <Stack spacing={1.5} alignItems={'center'} textAlign={'center'}>
        {showLogo && (
          <Image src={PelicanLogo} alt={''} width={48} height={48} priority />
        )}
        <Typography
          variant={'h5'}
          component={'h1'}
          sx={{ fontWeight: 600, lineHeight: 1.2 }}
        >
          {title}
        </Typography>
        {description && (
          <Typography variant={'body2'} color={'text.secondary'}>
            {description}
          </Typography>
        )}
      </Stack>
      {children}
    </Stack>
  </Paper>
);

export default AuthPanel;
