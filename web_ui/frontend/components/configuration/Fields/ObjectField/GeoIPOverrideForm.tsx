import React, { useCallback, useState } from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';

import {
  FormProps,
  ModalProps,
  GeoIPOverride,
  Institution,
  StringField,
} from '@/components/configuration';
import {
  verifyIpAddress,
  verifyLongitude,
} from '@/components/configuration/util';

const verifyForm = (x: GeoIPOverride) => {
  return !(
    verifyIpAddress(x.ip) ||
    verifyLongitude(x.coordinate.lat) ||
    verifyLongitude(x.coordinate.long)
  );
};

// Function to create a default GeoIPOverride object
const createDefaultGeoIPOverride = (): GeoIPOverride => ({
  ip: '',
  coordinate: {
    lat: '',
    long: '',
  },
});

const GeoIPOverrideForm = ({ onSubmit, value }: FormProps<GeoIPOverride>) => {
  const [geoIP, setGeoIP] = useState<GeoIPOverride>(
    value || createDefaultGeoIPOverride()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(geoIP)) {
      return;
    }
    onSubmit(geoIP);
  }, [geoIP]);

  return (
    <>
      <Box my={2}>
        <StringField
          onChange={(e) => setGeoIP({ ...geoIP, ip: e })}
          name={'IP'}
          value={geoIP?.ip}
          verify={verifyIpAddress}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={(e) =>
            setGeoIP({ ...geoIP, coordinate: { ...geoIP?.coordinate, lat: e } })
          }
          name={'Latitude'}
          value={geoIP?.coordinate?.lat}
          verify={verifyLongitude}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={(e) =>
            setGeoIP({
              ...geoIP,
              coordinate: { ...geoIP?.coordinate, long: e },
            })
          }
          name={'Longitude'}
          value={geoIP?.coordinate?.long}
          verify={verifyLongitude}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default GeoIPOverrideForm;
