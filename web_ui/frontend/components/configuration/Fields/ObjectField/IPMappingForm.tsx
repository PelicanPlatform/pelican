import React, { useCallback } from 'react';
import { Box, Button, TextField } from '@mui/material';

import {
  FormProps,
  Action,
  IPMapping,
  IPMappingFine,
  StringField,
} from '@/components/configuration';
import { verifyIpAddress } from '@/components/configuration/util';

const verifySourceIp = (x: string) => {
  const isValidIp =
    /^(?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(?!$)|$)){4}$/.test(x);
  const isValidAll = x.toLowerCase() == 'all';
  return isValidIp || isValidAll ? undefined : "Must provide IP or 'all'";
};

const verifyForm = (x: IPMappingFine) => {
  return (
    verifySourceIp(x.source) == undefined &&
    verifyIpAddress(x.dest) == undefined
  );
};

const createDefaultIPMapping = (): IPMappingFine => {
  return {
    source: '',
    dest: '',
  };
};

const IPMappingForm = ({ onSubmit, value }: FormProps<IPMapping>) => {
  const valueAsIPMappingFine: IPMappingFine =
    value !== undefined && 'all' in value ? { source: 'all', dest: value.all } : value;

  const [ipMapping, setIPMapping] = React.useState<IPMappingFine>(
    valueAsIPMappingFine || createDefaultIPMapping()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(ipMapping)) {
      return;
    }

    if (ipMapping.source == 'All') {
      onSubmit({
        all: ipMapping.dest,
      });
    } else {
      onSubmit(ipMapping);
    }
  }, [ipMapping]);

  return (
    <>
      <Box my={2}>
        <StringField
          onChange={(e) => setIPMapping({ ...ipMapping, source: e })}
          name={'Source'}
          value={ipMapping.source}
          verify={verifySourceIp}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={(e) => setIPMapping({ ...ipMapping, dest: e })}
          name={'Destination'}
          value={ipMapping?.dest}
          verify={verifyIpAddress}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>Submit</Button>
    </>
  );
};

export default IPMappingForm;
