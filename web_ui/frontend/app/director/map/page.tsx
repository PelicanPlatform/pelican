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
import { useContext } from 'react';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { ServerGeneral } from '@/types';
import { alertOnError } from '@/helpers/util';
import { getDirectorServers } from '@/helpers/get';

export default function Page() {
  const dispatch = useContext(AlertDispatchContext);

  const { data } = useSWR<ServerGeneral[] | undefined>(
    'getDirectorServers',
    async () =>
      await alertOnError(
        getDirectorServers,
        'Failed to fetch servers',
        dispatch
      )
  );

  return <ServerMap servers={data} />;
}
