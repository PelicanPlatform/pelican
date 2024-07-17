/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

import { Box, Tooltip } from '@mui/material';

import { ButtonLink, Sidebar } from '@/components/layout/Sidebar';
import Link from 'next/link';
import Image from 'next/image';
import PelicanLogo from '@/public/static/images/PelicanPlatformLogo_Icon.png';
import IconButton from '@mui/material/IconButton';
import BuildIcon from '@mui/icons-material/Build';
import Main from '@/components/layout/Main';
import { PaddedContent } from '@/components/layout';
import { Dashboard, MapOutlined } from '@mui/icons-material';

export const metadata = {
  title: 'Pelican Cache',
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
        <ButtonLink title={'Cache'} href={'/cache'}>
          <Dashboard />
        </ButtonLink>
        <ButtonLink title={'Config'} href={'/config/'}>
          <BuildIcon />
        </ButtonLink>
      </Sidebar>
      <Main>
        <PaddedContent>{children}</PaddedContent>
      </Main>
    </Box>
  );
}
