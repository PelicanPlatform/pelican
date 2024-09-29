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
'use client';

import { Box, Tooltip } from '@mui/material';
import Link from 'next/link';
import { Build, Dashboard, Public } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import useSWR from 'swr';

import { ButtonLink, Sidebar } from '@/components/layout/Sidebar';
import { getExportData } from '../DataExportTable';

export const OriginSidebar = () => {
  const { data, error } = useSWR('getDataExport', getExportData);

  if (error) {
    console.log('Error fetching data exports: ' + error);
  }

  return (
    <Sidebar>
      <ButtonLink title={'Dashboard'} href={'/origin/'}>
        <Dashboard />
      </ButtonLink>
      {data?.type === 'globus' && (
        <ButtonLink title={'Globus Configurations'} href={'/origin/globus/'}>
          <Public />
        </ButtonLink>
      )}
      <ButtonLink title={'Config'} href={'/config/'}>
        <Build />
      </ButtonLink>
    </Sidebar>
  );
};
