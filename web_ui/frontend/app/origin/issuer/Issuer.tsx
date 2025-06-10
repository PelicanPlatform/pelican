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

import React, {useState, useReducer, useCallback, useMemo, useContext} from 'react';
import {
  Box,
  Typography,
  FormGroup,
  FormControlLabel,
  Switch,
  Grid,
  Button,
  Snackbar,
} from '@mui/material';
import { green, grey } from '@mui/material/colors';
import Link from 'next/link';

import {
  ParameterMetadataRecord,
  ParameterValueRecord,
  submitConfigChange,
} from '@/components/configuration';
import { isEqual, merge } from 'lodash';
import StatusSnackBar, {
  StatusSnackBarProps,
} from '@/components/StatusSnackBar';
import { ConfigDisplay } from '@/app/config/components';
import {ConfigurationContext} from "@/components/ConfigurationProvider/ConfigurationProvider";

export function Issuer({ metadata }: { metadata: ParameterMetadataRecord }) {

  const { configuration, patch, merged, setPatch, mutate, submit } = useContext(ConfigurationContext);

  const [status, setStatus] = useState<StatusSnackBarProps | undefined>(
    undefined
  );

  const updatesPending = useMemo(() => {
    return !Object.keys(patch)
      .filter((key) => key !== 'Origin.EnableIssuer')
      .every((key) => isEqual(patch[key], configuration?.[key]));
  }, [configuration, patch]);

  const submitPatch = useCallback(async (patch: any) => {
    setStatus({ message: 'Submitting', severity: 'info' });
    try {
      await submit()
      setStatus(undefined);
    } catch (e) {
      setStatus({ message: (e as Error).toString(), severity: 'error' });
      setPatch({});
      mutate();
    }
  }, [submit, mutate, setPatch, setStatus]);

  return (
    <Box>
      <Grid container>
        <Grid item xs={12} lg={8}>
          <Box maxWidth={"80ch"}>
            <Typography variant={'h4'} gutterBottom>Origin Token Issuer</Typography>
            <Typography variant={'body1'} gutterBottom>
              The Origin Token Issuer is responsible for issuing tokens to users
              and applications accessing the Origin&#39;s files. If you
              are unsure how to proceed the <b>Configuration Flow</b> will guide
              you through the setup process.
            </Typography>
          </Box>
          <Box my={2}>
            <Link href={'./setup/client/'}>
              <Button variant={'outlined'}>Configuration Flow</Button>
            </Link>
          </Box>
          <Typography variant={'h5'} gutterBottom>Issuer Configuration</Typography>
          <BooleanToggle
            label={'Enable Issuer'}
            value={merged?.['Origin.EnableIssuer'] as boolean | false}
            onClick={(x) => {
              const patch = { 'Origin.EnableIssuer': x };
              setPatch(patch);
              submitPatch(patch);
              mutate();
            }}
          />
          {merged?.['Origin.EnableIssuer'] && (
            <Box pt={1}>
              <IssuerConfigForm
                config={configuration}
                patch={patch}
                configView={merged}
                metadata={metadata}
                setPatch={setPatch}
              />
            </Box>
          )}
          <Snackbar
            anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
            open={updatesPending}
            message='Save Changes'
            action={
              <Box>
                <Button
                  onClick={async () => {
                    try {
                      await submitConfigChange(patch);
                      setStatus({
                        message: 'Changes Saved, Restarting Server',
                      });
                      // Refresh the page after 3 seconds
                      setTimeout(() => {
                        mutate();
                        setStatus(undefined);
                        setPatch({});
                      }, 3000);
                    } catch (e) {
                      setStatus({
                        severity: 'error',
                        message: (e as string).toString(),
                      });
                    }
                  }}
                >
                  Save
                </Button>
                <Button
                  onClick={() => {
                    setPatch({});
                  }}
                >
                  Clear
                </Button>
              </Box>
            }
          />
        </Grid>
      </Grid>
      {status && <StatusSnackBar key={status.message} {...status} />}
    </Box>
  );
}

// Here we pull out the various groups that we want to handle differently
const OIDCGroupConfig = [
  'Issuer.OIDCGroupClaim',
  'Issuer.GroupFile',
  'Issuer.GroupRequirements',
];

const OIDCConfig = [
  'Issuer.OIDCAuthenticationRequirements',
  'Issuer.OIDCAuthenticationUserClaim',
  'OIDC.ClientIDFile',
  'OIDC.ClientID',
  'OIDC.ClientSecretFile',
  'OIDC.DeviceAuthEndpoint',
  'OIDC.TokenEndpoint',
  'OIDC.UserInfoEndpoint',
  'OIDC.AuthorizationEndpoint',
  'OIDC.Issuer',
  'OIDC.ClientRedirectHostname',
];

const OIDCToggles = ['Issuer.AuthenticationSource', 'Issuer.GroupSource'];

interface IssuerConfigFormProps {
  metadata: ParameterMetadataRecord;
  config?: ParameterValueRecord;
  patch: ParameterValueRecord;
  configView: ParameterValueRecord;
  setPatch: (fieldPatch: any) => void;
}

const IssuerConfigForm = ({
  metadata,
  config,
  patch,
  configView,
  setPatch,
}: IssuerConfigFormProps) => {
  return (
    <>
      <ConfigDisplay
        config={config}
        patch={patch}
        metadata={getKeyValues('Issuer.AuthenticationSource', metadata)}
        onChange={setPatch}
        omitLabels={true}
        showDescription={true}
      />
      {configView['Issuer.AuthenticationSource'] == 'OIDC' && (
        <Box p={1} pl={2} pt={0} bgcolor={grey[50]} borderLeft={1}>
          <ConfigDisplay
            config={config}
            patch={patch}
            metadata={getKeyValues(OIDCConfig, metadata)}
            onChange={setPatch}
            omitLabels={true}
            showDescription={true}
          />
          <ConfigDisplay
            config={config}
            patch={patch}
            metadata={getKeyValues('Issuer.GroupSource', metadata)}
            onChange={setPatch}
            omitLabels={true}
            showDescription={true}
          />
          {['file', 'oidc'].includes(
            configView['Issuer.GroupSource'] as string
          ) && (
            <Box p={1} pl={2} pt={0} bgcolor={grey[100]} borderLeft={1}>
              <ConfigDisplay
                config={config}
                patch={patch}
                metadata={getKeyValues(OIDCGroupConfig, metadata)}
                onChange={setPatch}
                omitLabels={true}
                showDescription={true}
              />
            </Box>
          )}
        </Box>
      )}
      {
        // display the rest of the fields
      }
      <ConfigDisplay
        config={config}
        patch={patch}
        metadata={getKeyValues(
          Object.keys(metadata).filter(
            (k) =>
              !OIDCConfig.includes(k) &&
              !OIDCGroupConfig.includes(k) &&
              !OIDCToggles.includes(k)
          ),
          metadata
        )}
        onChange={setPatch}
        omitLabels={true}
        showDescription={true}
      />
    </>
  );
};

const BooleanToggle = ({
  label,
  value,
  onClick,
}: {
  label: string;
  value: boolean;
  onClick: (x: boolean) => void;
}) => {
  const [disabled, setDisabled] = useState(false);

  return (
    <Box
      sx={{
        p: 1,
        borderRadius: 1,
        bgcolor: value ? green[200] : 'inherit',
      }}
    >
      <FormGroup>
        <FormControlLabel
          control={
            <Switch
              disabled={disabled}
              checked={value}
              onChange={(e) => {
                setDisabled(true);
                setTimeout(setDisabled, 4000);
                onClick(e.target.checked);
              }}
            />
          }
          label={label}
        />
      </FormGroup>
    </Box>
  );
};

/**
 * Create a new dictionary from an object that includes only the provided keys
 * @param key
 * @param item
 */
const getKeyValues = (key: string | string[], item: Record<string, any>) => {
  const keyValues: Record<string, any> = {};
  if (Array.isArray(key)) {
    key.forEach((k) => {
      keyValues[k] = item[k];
    });
  } else {
    keyValues[key] = item[key];
  }
  return keyValues;
};
