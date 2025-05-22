import { ReactElement } from 'react';
import ConfigurationProvider from '@/components/ConfigurationProvider/ConfigurationProvider';

import IssuerFlowContainer from '@/app/origin/issuer/components/IssuerFlowContainer';

import _metadata from '@/public/data/parameters.json';
import { ParameterMetadataList } from '@/components/configuration';
import { InlineAlertProvider } from '@/components/AlertProvider';

const Layout = ({ children }: { children: ReactElement }) => {
  return (
    <ConfigurationProvider>
      <InlineAlertProvider>
        <IssuerFlowContainer>{children}</IssuerFlowContainer>
      </InlineAlertProvider>
    </ConfigurationProvider>
  );
};

export default Layout;
