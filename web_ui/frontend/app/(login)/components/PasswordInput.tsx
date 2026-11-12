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

import * as React from 'react';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import TextField from '@mui/material/TextField';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';

interface PasswordInputProps {
  TextFieldProps?: React.ComponentProps<typeof TextField>;
}

/**
 * A full-width password field with a show / hide toggle.
 *
 * Fills whatever the caller puts it in and carries no margin of its own, so
 * the form decides the spacing. It also no longer hard-codes an element id:
 * the password-setup page renders two of these, and two elements sharing an
 * id is invalid markup that confuses assistive technology.
 */
export default function PasswordInput({ TextFieldProps }: PasswordInputProps) {
  const [showPassword, setShowPassword] = React.useState(false);

  const toggle = () => setShowPassword((show) => !show);

  return (
    <TextField
      label={'Admin Password'}
      autoComplete={'current-password'}
      name={'password'}
      fullWidth
      type={showPassword ? 'text' : 'password'}
      {...TextFieldProps}
      slotProps={{
        ...TextFieldProps?.slotProps,
        input: {
          endAdornment: (
            <InputAdornment position={'end'}>
              <IconButton
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                onClick={toggle}
                // Keeps focus in the field so toggling never drops the caret.
                onMouseDown={(e) => e.preventDefault()}
                edge={'end'}
              >
                {showPassword ? <VisibilityOff /> : <Visibility />}
              </IconButton>
            </InputAdornment>
          ),
          ...TextFieldProps?.slotProps?.input,
        },
      }}
    />
  );
}
