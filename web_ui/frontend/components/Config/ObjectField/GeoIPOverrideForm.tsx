import { GeoIPOverride, Institution } from '@/components/Config/index';
import React from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';

import {
  FormProps,
  ModalProps,
} from '@/components/Config/ObjectField/ObjectField';
import { StringField } from '@/components/Config';
import { verifyIpAddress, verifyLongitude } from '@/components/Config/util';

const verifyForm = (x: GeoIPOverride) => {
  if (
    verifyIpAddress(x.ip) ||
    verifyLongitude(x.coordinate.lat) ||
    verifyLongitude(x.coordinate.long)
  ) {
    return false;
  }
  return true;
};

const GeoIPOverrideForm = ({ onSubmit, value }: FormProps<GeoIPOverride>) => {
  const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const formData = new FormData(form);
    const value = {
      ip: formData.get('ip') as string,
      coordinate: {
        lat: formData.get('latitude') as string,
        long: formData.get('longitude') as string,
      },
    };

    if (!verifyForm(value)) {
      return;
    }

    onSubmit(value);
  };

  return (
    <form onSubmit={submitHandler}>
      <Box my={2}>
        <StringField
          onChange={() => {}}
          name={'IP'}
          value={value?.ip}
          verify={verifyIpAddress}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={() => {}}
          name={'Latitude'}
          value={value?.coordinate?.lat}
          verify={verifyLongitude}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={() => {}}
          name={'Longitude'}
          value={value?.coordinate?.long}
          verify={verifyLongitude}
        />
      </Box>
      <Button type={'submit'}>Submit</Button>
    </form>
  );
};

export default GeoIPOverrideForm;
