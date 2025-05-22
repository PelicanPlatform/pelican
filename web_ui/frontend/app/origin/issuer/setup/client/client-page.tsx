'use client';

import { Box, TextField, Typography } from '@mui/material';
import { use, useContext } from 'react';
import { ConfigurationContext } from '@/components/ConfigurationProvider/ConfigurationProvider';
import { ParameterMetadataRecord } from '@/components/configuration';

const ClientPage = ({ metadata }: { metadata: ParameterMetadataRecord }) => {
  const { merged, patch, setPatch } = useContext(ConfigurationContext);

  const clientIdFileIsSet =
    merged['OIDC.ClientIDFile'] !== '' &&
    merged['OIDC.ClientIDFile'] !== undefined;
  const clientIdIsSet =
    merged['OIDC.ClientID'] !== '' && merged['OIDC.ClientID'] !== undefined;

  return (
    <>
      <Typography variant={'subtitle1'} component={'h2'} gutterBottom>
        OpenID Connect Client Configuration
      </Typography>
      <Typography variant={'body1'} gutterBottom>
        This set of configuration sets up the Origin&apos;s OpenID Connect
        Client. The client is responsible for authenticating users that wish to
        access the Origin&apos;s files.
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        There are many &quot;Providers&quot; that can be used to create a OpenID
        Connect Client. Some common options you might be familiar with are
        Google, Microsoft and Facebook. We suggest{' '}
        <a href={'https://www.cilogon.org/oidc'}>CILogon</a>, a product out of{' '}
        <a href={'https://www.ncsa.illinois.edu/'}>NCSA</a> that integrates well
        with campus identity providers and Google. You can register a CILogon
        client on their{' '}
        <a href={'https://www.cilogon.org/oidc/register'}>registration page</a>.
      </Typography>
      <Box mt={3}>
        <TextField
          id={'client_secret_file'}
          label='Client Secret File Path'
          placeholder='Enter Client Secret File Path'
          fullWidth
          onChange={(event) => {
            setPatch({ 'OIDC.ClientSecretFile': event.target.value });
          }}
          margin='normal'
          helperText='Path to the file containing the Client Secret.'
          value={merged['OIDC.ClientSecretFile'] || ''}
        />
        <TextField
          id='client_id_file'
          label='Client ID File Path'
          placeholder='Enter Client ID File Path'
          fullWidth
          onChange={(event) => {
            setPatch({ 'OIDC.ClientIDFile': event.target.value });
          }}
          margin='normal'
          helperText='Path to the file containing the Client ID. Mutually exclusive with ClientID'
          disabled={clientIdIsSet}
          value={merged['OIDC.ClientIDFile'] || ''}
        />
        <TextField
          id='client_id'
          label='Client ID'
          placeholder='Enter Client ID'
          fullWidth
          onChange={(event) => {
            setPatch({ 'OIDC.ClientID': event.target.value });
          }}
          margin='normal'
          helperText='The Client ID string. Mutually exclusive with ClientIDFile'
          disabled={clientIdFileIsSet}
          value={merged['OIDC.ClientID'] || ''}
        />
      </Box>
    </>
  );
};

export default ClientPage;
