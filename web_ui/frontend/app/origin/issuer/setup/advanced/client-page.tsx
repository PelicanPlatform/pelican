import { Typography } from '@mui/material';
import { use } from 'react';
import { ParameterMetadataRecord } from '@/components/configuration';

const ClientPage = ({ metadata }: { metadata: ParameterMetadataRecord }) => {
  return (
    <>
      <Typography variant={'subtitle1'} component={'h2'} gutterBottom>
        Advanced Issuer Configuration
      </Typography>
      <Typography variant={'body1'} gutterBottom>
        This set of configuration is not required for the basic setup of the
        Origin Issuer. It is provided for advanced users that wish to further
        customize the behavior of the Origin Issuer.
      </Typography>
    </>
  );
};

export default ClientPage;
