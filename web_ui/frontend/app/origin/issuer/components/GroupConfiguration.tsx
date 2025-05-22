import { Box, MenuItem, Select, Typography } from '@mui/material';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import { grey } from '@mui/material/colors';
import { ConfigDisplay } from '@/app/config/components';
import { Code } from '@/components';
import {
  ParameterMetadataRecord,
  ParameterValueRecord,
} from '@/components/configuration';
import { useContext, useEffect } from 'react';
import { ConfigurationContext } from '@/components/ConfigurationProvider/ConfigurationProvider';
import { InlineAlertDispatchContext } from '@/components/AlertProvider';

const GroupConfiguration: React.FC<{ metadata: ParameterMetadataRecord }> = ({
  metadata,
}) => {
  const { configuration, patch, merged, setPatch } =
    useContext(ConfigurationContext);

  const dispatch = useContext(InlineAlertDispatchContext);

  useEffect(() => {
    // Check if there are group requirements we have a valid group source
    if (merged['Issuer.GroupSource']) {
      // Check oidc is configured correctly
      if (
        merged['Issuer.GroupSource'] == 'oidc' &&
        !merged['Issuer.OIDCGroupClaim']
      ) {
        dispatch({
          type: 'openAlert',
          payload: {
            message: 'OIDC Group Source is set but no OIDC Group Claim is set',
            title: 'Missing information',
            onClose: () => dispatch({ type: 'closeAlert' }),
            alertProps: {
              severity: 'info',
            },
          },
        });
      }

      // Check file is configured correctly
      if (
        merged['Issuer.GroupSource'] == 'file' &&
        (!merged['Issuer.GroupFile'] ||
          !merged['Issuer.OIDCAuthenticationUserClaim'])
      ) {
        dispatch({
          type: 'openAlert',
          payload: {
            message:
              "Group Source is set to file, but you haven't defined a GroupFile and OIDCAuthenticationUserClaim",
            title: 'Missing information',
            onClose: () => dispatch({ type: 'closeAlert' }),
            alertProps: {
              severity: 'info',
            },
          },
        });
      }
    }
  }, [merged, dispatch]);

  return (
    <>
      <Typography variant={'h6'} gutterBottom>
        Determine Group Source
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        The group source will determine where we get the group information for
        an authenticated user.
      </Typography>
      <ol>
        <li>
          <b>OIDC</b>: The group information will be retrieved from a claim in
          the OIDC token.
        </li>
        <li>
          <b>File</b>: The group information will be retrieved from a json file
          of group arrays keyed by user claim value.
        </li>
      </ol>
      <FormControl fullWidth size={'small'} sx={{ mt: 2 }}>
        <InputLabel id='group-source-label'>Group Source</InputLabel>
        <Select
          labelId='group-source-label'
          id='group-source-select'
          value={(merged['Issuer.GroupSource'] as string) || ''}
          label='Group Source'
          onChange={(e) => setPatch({ 'Issuer.GroupSource': e.target.value })}
        >
          <MenuItem value={''}>None</MenuItem>
          <MenuItem value={'oidc'}>OIDC</MenuItem>
          <MenuItem value={'file'}>File</MenuItem>
        </Select>
      </FormControl>
      {merged['Issuer.GroupSource'] === 'file' && (
        <Box p={1} pl={2} pt={0} bgcolor={grey[50]} borderLeft={1}>
          <Typography variant={'body2'} gutterBottom sx={{ pt: 2 }}>
            The user claim will be used as the key to the group array present in
            your json file.
          </Typography>
          <ConfigDisplay
            config={configuration}
            patch={patch}
            metadata={{
              'Issuer.OIDCAuthenticationUserClaim':
                metadata['Issuer.OIDCAuthenticationUserClaim'],
            }}
            onChange={setPatch}
            omitLabels={true}
            showDescription={false}
          />
          <Typography variant={'body2'} gutterBottom sx={{ mt: 2 }}>
            The group file path points to a file in format:
          </Typography>
          <Code>
            {[
              `"user_claim_a": ["group_a", "group_b"]`,
              `"user_claim_b": ["group_c"]`,
            ].join(',\n')}
          </Code>
          <ConfigDisplay
            config={configuration}
            patch={patch}
            metadata={{ 'Issuer.GroupFile': metadata['Issuer.GroupFile'] }}
            onChange={setPatch}
            omitLabels={true}
            showDescription={false}
          />
        </Box>
      )}
      {merged['Issuer.GroupSource'] === 'oidc' && (
        <Box p={1} pl={2} pt={0} bgcolor={grey[50]} borderLeft={1}>
          <Typography variant={'body2'} gutterBottom sx={{ pt: 2 }}>
            The OIDC claim that points to a comma separated list of groups or
            array.
          </Typography>
          <ConfigDisplay
            config={configuration}
            patch={patch}
            metadata={{
              'Issuer.OIDCGroupClaim': metadata['Issuer.OIDCGroupClaim'],
            }}
            onChange={setPatch}
            omitLabels={true}
            showDescription={false}
          />
        </Box>
      )}
    </>
  );
};

export default GroupConfiguration;
