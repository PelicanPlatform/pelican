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
import { GroupConfiguration, TabPanel } from '@/app/origin/issuer/components';
import a11yProps from '@/app/origin/issuer/util/a11yProps';
import { InlineAlertDispatchContext } from '@/components/AlertProvider';

const ClientPage = ({ metadata }: { metadata: ParameterMetadataRecord }) => {
  const [tabIndex, setTabIndex] = useState<number>(0);

  return (
    <>
      <Typography variant={'subtitle1'} component={'h2'} gutterBottom>
        Broad Requirements
      </Typography>
      <Typography variant={'body1'} gutterBottom>
        Filter authenticated users by their claims and/or groups.
      </Typography>

      <Tabs value={tabIndex} onChange={(_, i) => setTabIndex(i)}>
        <Tab label={'Claim Requirements'} {...a11yProps(1)}></Tab>
        <Tab label={'Group Requirements'} {...a11yProps(2)}></Tab>
      </Tabs>

      <TabPanel value={tabIndex} index={0}>
        <UserClaimConfiguration metadata={metadata} />
      </TabPanel>
      <TabPanel value={tabIndex} index={1}>
        <GroupClaimConfiguration metadata={metadata} />
      </TabPanel>
    </>
  );
};

const UserClaimConfiguration: React.FC<{
  metadata: ParameterMetadataRecord;
}> = ({ metadata }) => {
  const { configuration, patch, setPatch } = useContext(ConfigurationContext);

  return (
    <>
      <Typography variant={'body2'} gutterBottom>
        <a
          href={'https://openid.net/specs/openid-connect-core-1_0.html#Claims'}
          target={'_blank'}
          rel='noopener noreferrer'
        >
          Claim
        </a>{' '}
        requirements that users must meet to be granted access to the Origin.
      </Typography>
      <ConfigDisplay
        config={configuration}
        patch={patch}
        metadata={{
          'Issuer.OIDCAuthenticationRequirements':
            metadata['Issuer.OIDCAuthenticationRequirements'],
        }}
        onChange={setPatch}
        omitLabels={true}
        showDescription={true}
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
        Define Required Groups
      </Typography>
      <ConfigDisplay
        config={configuration}
        patch={patch}
        metadata={{
          'Issuer.GroupRequirements': metadata['Issuer.GroupRequirements'],
        }}
        onChange={setPatch}
        omitLabels={true}
        showDescription={false}
      />
    </>
  );
};

export default ClientPage;
