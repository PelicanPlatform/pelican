import { Capability, Institution } from '@/components/Config/index.d';
import React from 'react';
import { Box, Button } from '@mui/material';

import {
  FormProps,
  ModalProps,
} from '@/components/Config/ObjectField/ObjectField';
import { MultiSelectField, SelectField, StringField } from '../../Config';
import { Export } from '@/components/Config/index.d';

const verifyForm = (x: Export) => {
  return (
    x.storageprefix != '' &&
    x.federationprefix != '' &&
    x.capabilities.length > 0
  );
};

const ExportForm = ({ onSubmit, value }: FormProps<Export>) => {
  const [storagePrefix, setStoragePrefix] = React.useState<string>(
    value?.storageprefix || ''
  );
  const [federationPrefix, setFederationPrefix] = React.useState<string>(
    value?.federationprefix || ''
  );
  const [capabilities, setCapabilities] = React.useState<Capability[]>(
    value?.capabilities || []
  );
  const [sentinelLocation, setSentinelLocation] = React.useState<string>(
    value?.sentinellocation || ''
  );

  const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const exportValue = {
      storageprefix: storagePrefix,
      federationprefix: federationPrefix,
      capabilities: capabilities,
      sentinellocation: sentinelLocation,
    };

    if (!verifyForm(exportValue)) {
      return;
    }

    onSubmit(exportValue);
  };

  return (
    <form onSubmit={submitHandler}>
      <Box my={2}>
        <StringField
          name={'StoragePrefix'}
          value={storagePrefix}
          onChange={setStoragePrefix}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'FederationPrefix'}
          value={federationPrefix}
          onChange={setFederationPrefix}
        />
      </Box>
      <Box mb={2}>
        <MultiSelectField<Capability>
          name={'Capabilities'}
          value={capabilities}
          onChange={setCapabilities}
          possibleValues={[
            'PublicReads',
            'DirectReads',
            'Writes',
            'Listings',
            'Reads',
          ]}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'SentinelLocation'}
          value={sentinelLocation}
          onChange={setSentinelLocation}
        />
      </Box>
      <Button type={'submit'}>Submit</Button>
    </form>
  );
};

export default ExportForm;
