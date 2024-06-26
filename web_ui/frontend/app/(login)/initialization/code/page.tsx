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

import { Box, Typography, Grow } from '@mui/material';
import { useRouter } from 'next/navigation';
import { useState } from 'react';

import CodeInput, { Code } from '../../components/CodeInput';
import LoadingButton from '../../components/LoadingButton';
import { getErrorMessage } from '@/helpers/util';

export default function Home() {
  const router = useRouter();
  let [code, _setCode] = useState<Code>([
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
  ]);
  let [loading, setLoading] = useState(false);
  let [error, setError] = useState<string | undefined>(undefined);

  const setCode = (code: Code) => {
    _setCode(code);
    setError(undefined);

    if (!code.includes(undefined)) {
      submit(code.map((x) => x!.toString()).join(''));
    }
  };

  async function submit(code: string) {
    setLoading(true);

    try {
      let response = await fetch('/api/v1.0/auth/initLogin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code: code,
        }),
      });

      if (response.ok) {
        router.push('../password/');
      } else {
        setLoading(false);
        setError(await getErrorMessage(response));
      }
    } catch {
      setLoading(false);
      setError('Could not connect to server');
    }
  }

  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();

    if (!code.includes(undefined)) {
      submit(code.map((x) => x!.toString()).join(''));
    }
  }

  return (
    <>
      <Box m={'auto'} mt={12} display={'flex'} flexDirection={'column'}>
        <Box>
          <Typography textAlign={'center'} variant={'h3'} component={'h3'}>
            Activate Website
          </Typography>
          <Typography textAlign={'center'} variant={'h6'} component={'p'}>
            Enter the activation code displayed on the command line
          </Typography>
        </Box>
        <Box pt={3} mx={'auto'}>
          <form onSubmit={onSubmit} action='#'>
            <CodeInput setCode={setCode} length={6} />
            <Box mt={2} display={'flex'} flexDirection={'column'}>
              <Grow in={error !== undefined}>
                <Typography
                  textAlign={'center'}
                  variant={'subtitle2'}
                  color={'error.main'}
                  mb={1}
                >
                  {error}
                </Typography>
              </Grow>
              <LoadingButton
                variant='outlined'
                sx={{ margin: 'auto' }}
                color={'primary'}
                type={'submit'}
                loading={loading}
              >
                <span>Activate</span>
              </LoadingButton>
            </Box>
          </form>
        </Box>
      </Box>
    </>
  );
}
