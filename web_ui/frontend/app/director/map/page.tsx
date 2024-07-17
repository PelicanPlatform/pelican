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

'use client';

import { Box } from '@mui/material';
import useSWR from 'swr';
import { Server } from '@/index';
import { ServerMap } from '@/components/Map';

export default function Page() {
  const { data } = useSWR<Server[]>('getServers', getServers);

  return (
    <Box width={'100%'}>
      <ServerMap servers={data} />
    </Box>
  );
}

const getServers = async (): Promise<Server[]> => {
  const url = new URL('/api/v1.0/director_ui/servers', window.location.origin);

  let response = await fetch(url);
  if (response.ok) {
    const responseData: Server[] = await response.json();
    responseData.sort((a, b) => a.name.localeCompare(b.name));
    return responseData;
  }

  throw new Error('Failed to fetch servers');
};
