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

import Image from 'next/image';
import Link from 'next/link';
import { Box, IconButton, Typography } from '@mui/material';

import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';
import GithubIcon from '@/public/static/images/github-mark.png';

/** Height of the bar in pixels, for anything that needs to sit below it. */
export const HEADER_HEIGHT = 64;

/**
 * The slim top bar on pages that have no navigation rail: login and the
 * initialization flow, the landing page, and invite redemption.
 *
 * It sits in the document flow and sticks to the top, so the pages beneath
 * it no longer have to reserve a hand-measured gap for a fixed element. The
 * previous version was the Next.js starter template's blurred conic-gradient
 * banner with a scroll listener it never removed; a paper surface with a
 * hairline rule matches the rail the rest of the UI now uses.
 */
export const Header = ({ text }: { text: string }) => (
  <Box
    component={'header'}
    sx={{
      position: 'sticky',
      top: 0,
      zIndex: 'appBar',
      height: HEADER_HEIGHT,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      px: { xs: 2, md: 3 },
      bgcolor: 'background.paper',
      borderBottom: 1,
      borderColor: 'divider',
    }}
  >
    <Box
      component={Link}
      href={'/'}
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        color: 'text.primary',
      }}
    >
      <Image src={PelicanLogo} alt={''} width={32} height={32} priority />
      <Typography
        variant={'h6'}
        component={'span'}
        sx={{ fontWeight: 600, lineHeight: 1 }}
      >
        {text}
      </Typography>
    </Box>
    <IconButton
      component={'a'}
      href={'https://github.com/PelicanPlatform'}
      target={'_blank'}
      rel={'noopener noreferrer'}
      aria-label={'Pelican Platform on GitHub'}
    >
      <Image src={GithubIcon} alt={''} width={24} height={24} />
    </IconButton>
  </Box>
);
