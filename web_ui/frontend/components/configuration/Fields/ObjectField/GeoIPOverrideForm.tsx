import React, { useCallback, useMemo, useState } from 'react';
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
import { SinglePointMap } from '@/components/Map';
import UpdateSinglePoint from '@/components/Map/UpdateSinglePoint';

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

  const lat = useMemo(() => {
    return parseFloat(geoIP?.coordinate?.lat);
  }, [geoIP]);

  const long = useMemo(() => {
    return parseFloat(geoIP?.coordinate?.long);
  }, [geoIP]);

  const setLatitude = useCallback((latitude: number) => {
    setGeoIP((geoIP) => {
      return { ...geoIP, coordinate: { ...geoIP?.coordinate, lat: latitude.toString() } }
    })
  }, []);

  const setLongitude = useCallback((longitude: number) => {
    setGeoIP((geoIP) => {
      return { ...geoIP, coordinate: { ...geoIP?.coordinate, long: longitude.toString() } }
    });
  }, []);

  return (
    <>
      <Box height={"200px"} width={"400px"} maxWidth={"100%"}>
        <UpdateSinglePoint latitude={lat} longitude={long} setLatitude={setLatitude} setLongitude={setLongitude} />
      </Box>
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
          onChange={(e) => setLatitude(parseFloat(e))}
          name={'Latitude'}
          value={geoIP?.coordinate?.lat}
          verify={verifyLongitude}
        />
      </Box>
      <Box mb={2}>
        <StringField
          onChange={(e) => setLongitude(parseFloat(e))}
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
