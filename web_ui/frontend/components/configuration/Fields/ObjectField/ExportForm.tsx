import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import {
  Capability,
  Institution,
  FormProps,
  ModalProps,
  MultiSelectField,
  SelectField,
  StringField,
  Export,
} from '@/components/configuration';

const verifyForm = (x: Export) => {
  return (
    x.storageprefix != '' &&
    x.federationprefix != '' &&
    x.capabilities.length > 0
  );
};

const createDefaultExport = (): Export => {
  return {
    storageprefix: '',
    federationprefix: '',
    capabilities: [],
    sentinellocation: '',
  };
};

const ExportForm = ({ onSubmit, value }: FormProps<Export>) => {
  const [storageExport, setStorageExport] = React.useState<Export>(
    value || createDefaultExport()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(storageExport)) {
      return;
    }
    onSubmit(storageExport);
  }, [storageExport]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'StoragePrefix'}
          value={storageExport.storageprefix}
          onChange={(e) =>
            setStorageExport({ ...storageExport, storageprefix: e })
          }
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'FederationPrefix'}
          value={storageExport.federationprefix}
          onChange={(e) =>
            setStorageExport({ ...storageExport, federationprefix: e })
          }
        />
      </Box>
      <Box mb={2}>
        <MultiSelectField<Capability>
          name={'Capabilities'}
          value={storageExport.capabilities}
          onChange={(e) =>
            setStorageExport({ ...storageExport, capabilities: e })
          }
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
          value={storageExport.sentinellocation}
          onChange={(e) =>
            setStorageExport({ ...storageExport, sentinellocation: e })
          }
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default ExportForm;
