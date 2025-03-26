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

import { Box, Button } from '@mui/material';
import SettingHeader from '@/app/settings/components/SettingHeader';
import TokenList from '@/app/settings/api/components/TokenList';
import Link from 'next/link';

export const metadata = {
  title: 'Token Settings',
  description: 'Pelican Token Settings',
};

export default function Home() {
  return (
    <Box width={'100%'}>
      <SettingHeader
        title={'Tokens'}
        description={
          'Used to access the Pelican API, including Prometheus metrics.'
        }
      />
      <Box mb={1}>
        <Link href='/settings/api/tokens/add'>
          <Button variant='contained' color='primary' size={'small'}>
            Generate Token
          </Button>
        </Link>
      </Box>
      <TokenList />
    </Box>
  );
}
