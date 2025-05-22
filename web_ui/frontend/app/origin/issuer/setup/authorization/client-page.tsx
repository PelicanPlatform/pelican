'use client';

import { Typography, Tabs, Tab, Box, Select, MenuItem } from '@mui/material';
import React, { useContext, useState } from 'react';
import {
  ParameterMetadataRecord,
  ParameterValueRecord,
} from '@/components/configuration';
import { ConfigDisplay } from '@/app/config/components';
import { ConfigurationContext } from '@/components/ConfigurationProvider/ConfigurationProvider';
import { Code } from '@/components';
import { GroupConfiguration } from '@/app/origin/issuer/components';

const ClientPage = ({ metadata }: { metadata: ParameterMetadataRecord }) => {
  const [tabIndex, setTabIndex] = useState<number>(1);
  const { configuration, merged, patch, setPatch } =
    useContext(ConfigurationContext);

  return (
    <>
      <Typography variant={'subtitle1'} component={'h2'} gutterBottom>
        Authorization Configuration
      </Typography>
      <Typography variant={'body1'} gutterBottom>
        Directory level permission configuration, applied after requirements.
      </Typography>

      <Tabs value={tabIndex} onChange={(_, i) => setTabIndex(i)}>
        <Tab label={'User Level'} {...a11yProps(1)}></Tab>
        <Tab label={'Group Level'} {...a11yProps(2)}></Tab>
        <Tab label={'Broad Access'} {...a11yProps(3)}></Tab>
      </Tabs>

      <TabPanel value={tabIndex} index={0}>
        <UserClaimConfiguration metadata={metadata} />
      </TabPanel>
      <TabPanel value={tabIndex} index={1}>
        <GroupClaimConfiguration metadata={metadata} />
      </TabPanel>
      <TabPanel value={tabIndex} index={2}>
        <BroadAccessConfiguration metadata={metadata} />
      </TabPanel>
    </>
  );
};

interface TabProps {
  configuration: ParameterValueRecord | undefined;
  patch: ParameterValueRecord;
  setPatch: (patch: Record<string, any>) => void;
  metadata: ParameterMetadataRecord;
}

const UserClaimConfiguration: React.FC<{
  metadata: ParameterMetadataRecord;
}> = ({ metadata }) => {
  const { configuration, patch, setPatch } = useContext(ConfigurationContext);

  return (
    <>
      <Typography variant={'h6'} gutterBottom>
        Define the User Claim
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        User level authorization requires you to decide what{' '}
        <a
          href={'https://openid.net/specs/openid-connect-core-1_0.html#Claims'}
          target={'_blank'}
          rel='noopener noreferrer'
        >
          claim
        </a>{' '}
        will be used as the username, <code>`sub`</code> is the default.
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
      <Typography variant={'h6'} gutterBottom mt={4}>
        Use `User Claim` in Authorization Template
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        The `User Claim` can now be referenced in the <b>user list</b>, and{' '}
        <b>$USER</b> substring found in the Origin&#39;s `Authorization
        Templates`.
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        If you would like to give users with claim values `user_claim_a` and
        `user_claim_b` read and modify access to the `/home` directory, you
        would add the following to your configuration:
        <code>
          <Code mt={2}>
            {[
              `- actions: ["read", "modify"]`,
              `  prefix: /home`,
              `  users: ["user_claim_a", "user_claim_b"]`,
            ].join('\n')}
          </Code>
        </code>
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        If you would like to give users with claim values `user_claim_a` read
        access to the `/home/user_claim_a` directory, you would add the
        following to your configuration:
        <code>
          <Code mt={2}>
            {[
              `- actions: ["read"]`,
              `  prefix: /home/$USER`,
              `  users: ["user_claim_a"]`,
            ].join('\n')}
          </Code>
        </code>
      </Typography>
      <ConfigDisplay
        config={configuration}
        patch={patch}
        metadata={{
          'Issuer.AuthorizationTemplates':
            metadata['Issuer.AuthorizationTemplates'],
        }}
        onChange={setPatch}
        omitLabels={true}
        showDescription={false}
      />
    </>
  );
};

const GroupClaimConfiguration: React.FC<{
  metadata: ParameterMetadataRecord;
}> = ({ metadata }) => {
  const { configuration, patch, setPatch } = useContext(ConfigurationContext);

  return (
    <>
      <GroupConfiguration metadata={metadata} />
      <Typography variant={'h6'} gutterBottom mt={3}>
        Use Group in Authorization Template
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        The group can now be referenced in the <b>group list</b>, and{' '}
        <b>$GROUP</b> substring found in the Origin&#39;s `Authorization
        Templates`.
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        If you would like to give users with claim values `user_claim_a` and
        `user_claim_b` read and modify access to the `/home` directory, you
        would add the following to your configuration:
        <code>
          <Code mt={2}>
            {[
              `- actions: ["read", "modify"]`,
              `  prefix: /home`,
              `  users: ["group_a", "group_b"]`,
            ].join('\n')}
          </Code>
        </code>
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        If you would like to give users with claim values `group_a` read access
        to the `/home/group_a` directory, you would add the following to your
        configuration:
        <code>
          <Code mt={2}>
            {[
              `- actions: ["read"]`,
              `  prefix: /home/$USER`,
              `  users: ["group_a"]`,
            ].join('\n')}
          </Code>
        </code>
      </Typography>
      <ConfigDisplay
        config={configuration}
        patch={patch}
        metadata={{
          'Issuer.AuthorizationTemplates':
            metadata['Issuer.AuthorizationTemplates'],
        }}
        onChange={setPatch}
        omitLabels={true}
        showDescription={false}
      />
    </>
  );
};

const BroadAccessConfiguration: React.FC<{
  metadata: ParameterMetadataRecord;
}> = ({ metadata }) => {
  const { configuration, patch, setPatch } = useContext(ConfigurationContext);

  return (
    <>
      <Typography variant={'body2'} gutterBottom>
        Broad access configuration is used to provide permissions to user who
        fit the previously defined requirements.
      </Typography>
      <Typography variant={'h6'} gutterBottom mt={3}>
        Use Group in Authorization Template
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        The group can now be referenced in the <b>group list</b>, and{' '}
        <b>$GROUP</b> substring found in the Origin&#39;s `Authorization
        Templates`.
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        If you would like to give users with claim values `user_claim_a` and
        `user_claim_b` read and modify access to the `/home` directory, you
        would add the following to your configuration:
        <code>
          <Code mt={2}>
            {[`- actions: ["read", "modify"]`, `  prefix: /home`].join('\n')}
          </Code>
        </code>
      </Typography>
      <Typography variant={'body2'} gutterBottom>
        If you would like to give users with claim values `group_a` read access
        to the `/home/group_a` directory, you would add the following to your
        configuration:
        <code>
          <Code mt={2}>
            {[
              `- actions: ["read"]`,
              `  prefix: /home/$USER`,
              `  users: ["group_a"]`,
            ].join('\n')}
          </Code>
        </code>
      </Typography>
      <ConfigDisplay
        config={configuration}
        patch={patch}
        metadata={{
          'Issuer.AuthorizationTemplates':
            metadata['Issuer.AuthorizationTemplates'],
        }}
        onChange={setPatch}
        omitLabels={true}
        showDescription={false}
      />
    </>
  );
};

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel = ({ children, value, index, ...other }: TabPanelProps) => {
  return (
    <Box
      role='tabpanel'
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </Box>
  );
};

function a11yProps(index: number, prefix: string = 'simple') {
  return {
    id: `${prefix}-tab-${index}`,
    'aria-controls': `${prefix}-tabpanel-${index}`,
  };
}

export default ClientPage;
