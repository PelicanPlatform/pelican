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

import { Stack } from '@mui/material';
import { useRouter } from 'next/navigation';
import { useContext, useState } from 'react';

import AuthPanel from '../../components/AuthPanel';
import LoadingButton from '../../components/LoadingButton';
import PasswordInput from '../../components/PasswordInput';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { resetLogin } from '@/helpers/api';

export default function Home() {
  const dispatch = useContext(AlertDispatchContext);

  const router = useRouter();
  let [password, _setPassword] = useState<string>('');
  let [confirmPassword, _setConfirmPassword] = useState<string>('');
  let [loading, setLoading] = useState(false);

  async function submit(password: string) {
    setLoading(true);

    let response = await alertOnError(
      async () => await resetLogin(password),
      'Could not login',
      dispatch
    );
    if (response) {
      router.push('/');
    } else {
      setLoading(false);
    }
  }

  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();

    if (password == confirmPassword) {
      submit(password);
    } else {
      dispatch({
        type: 'openAlert',
        payload: {
          alertProps: {
            severity: 'warning',
          },
          message: 'Passwords do not match',
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });
    }
  }

  const mismatch = confirmPassword !== '' && password !== confirmPassword;

  return (
    <AuthPanel
      title={'Set Password'}
      description={
        'This will become the admin password for this Pelican endpoint'
      }
    >
      <form onSubmit={onSubmit} action='#'>
        <Stack spacing={2}>
          <PasswordInput
            TextFieldProps={{
              autoComplete: 'new-password',
              onChange: (e) => _setPassword(e.target.value),
            }}
          />
          <PasswordInput
            TextFieldProps={{
              label: 'Confirm Password',
              autoComplete: 'new-password',
              onChange: (e) => _setConfirmPassword(e.target.value),
              // Only complain once something has been typed in the second
              // field; an empty confirmation is not yet a mismatch.
              error: mismatch,
              helperText: mismatch ? 'Passwords do not match' : ' ',
            }}
          />
          <LoadingButton
            variant='contained'
            size='large'
            fullWidth
            type={'submit'}
            loading={loading}
          >
            <span>Confirm</span>
          </LoadingButton>
        </Stack>
      </form>
    </AuthPanel>
  );
}
