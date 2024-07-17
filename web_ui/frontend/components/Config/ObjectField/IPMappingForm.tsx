import { Action, IPMapping, IPMappingFine } from '@/components/Config/index';
import React from 'react';
import { Box, Button, TextField } from '@mui/material';

import { FormProps } from '@/components/Config/ObjectField/ObjectField';
import { StringField } from '@/components/Config';
import { verifyIpAddress } from '@/components/Config/util';

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

const IPMappingForm = ({ onSubmit, value }: FormProps<IPMapping>) => {
  const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const formData = new FormData(form);

    let source = formData.get('source') as string;
    let destination = formData.get('destination') as string;

    let ipMapping = undefined;
    if (source == 'All') {
      ipMapping = {
        all: destination,
      };
    } else {
      ipMapping = {
        source: source,
        dest: destination,
      };
    }

    if (
      !verifyForm({
        source: source,
        dest: destination,
      })
    ) {
      return;
    }

    onSubmit(ipMapping);
  };

  return (
    <form onSubmit={submitHandler}>
      <Box my={2}>
        <StringField
          onChange={() => {}}
          name={'Source'}
          value={'all' in value ? 'all' : value?.source}
          verify={verifySourceIp}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={() => {}}
          name={'Destination'}
          value={'all' in value ? value.all : value?.dest}
          verify={verifyIpAddress}
        />
      </Box>
      <Button type={'submit'}>Submit</Button>
    </form>
  );
};

export default IPMappingForm;
