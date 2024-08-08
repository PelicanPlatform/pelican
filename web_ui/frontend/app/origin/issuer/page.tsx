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

import { useState, useReducer } from 'react';
import {
  Box,
  IconButton,
  Grid,
  Tooltip,
  Typography,
  FormGroup,
  FormControlLabel,
  Switch,
} from '@mui/material';
import { User } from '@/index';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { getErrorMessage } from '@/helpers/util';
import { Label } from '@mui/icons-material';
import { BooleanToggleButton } from '@/components';
import useSWR from 'swr';
import { getConfig } from '@/helpers/get';
import configPatchReducer, {
  ConfigAction,
  ConfigPatch,
} from '@/reducers/configPatch';

export default function Page() {
  const { data: config, error: configError } = useSWR(
    'issuerConfig',
    getConfig
  );

  const [configPatch, dispatchConfigPatch] = useReducer(configPatchReducer, {});

  const [] = useState();

  return (
    <AuthenticatedContent
      redirect={true}
      checkAuthentication={(u: User) => u?.role == 'admin'}
    >
      <Box width={'100%'}>
        <Typography variant={'h4'}>Issuer Configuration</Typography>
        <Box mt={2}>
          <Typography variant={'body1'}>
            The origins issuer is responsible for issuing access tokens for the
            data that it holds.
          </Typography>
          <BooleanToggleButton
            label={'Enable Issuer'}
            onChange={() => 'test'}
          />
        </Box>
      </Box>
    </AuthenticatedContent>
  );
}

const booleanToggle = ({
  label,
  value,
  onClick,
}: {
  label: string;
  value: boolean;
  onClick: () => void;
}) => {
  return (
    <Box onClick={onClick}>
      <FormGroup>
        <FormControlLabel control={<Switch value={value} />} label={label} />
      </FormGroup>
    </Box>
  );
};
