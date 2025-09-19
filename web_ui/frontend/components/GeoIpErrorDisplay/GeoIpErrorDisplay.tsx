/**
 * Table printing out the errors that occurred during the GeoIP lookup.
 */

import { useCallback, useContext, useMemo, useState } from 'react';
import {
  Button,
  Paper,
  Typography,
  CircularProgress,
  Box,
  ButtonGroup,
} from '@mui/material';
import useSWR from 'swr';

import { VectorResult } from '@/components';
import {
  GeoIPOverride,
  GeoIPOverrideForm,
  ParameterValueRecord,
  submitConfigChange,
} from '@/components/configuration';
import { alertOnError } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import ObjectModal from '@/components/configuration/Fields/ObjectField/ObjectModal';

import getOverriddenGeoIps from './getOverriddenGeoIps';
import getLastOverDay from './getLastOverDay';
import GeoIpErrorTable from './GeoIpErrorTable';

const GeoIpErrorDisplay = () => {
  const dispatch = useContext(AlertDispatchContext);

  // Get the IP errors from the last day
  const { data: serverIpErrors } = useSWR('geoip_server_errors', async () =>
    getLastOverDay('pelican_director_maxmind_server_errors_total')
  );
  const { data: clientIpErrors } = useSWR('geoip_client_errors', async () =>
    getLastOverDay('pelican_director_maxmind_client_errors_total')
  );

  const [activeView, setActiveView] = useState<MetricVariant>('server');

  const {
    data: config,
    mutate,
    error,
    isValidating,
  } = useSWR<ParameterValueRecord | undefined>(
    'getConfig',
    async () =>
      await alertOnError(getOverriddenGeoIps, 'Could not get config', dispatch)
  );

  // A function that filters out already patched IPs and sorts the rest by number of errors
  const transformIpErrors = useCallback(
    (ipErrors: VectorResult[] | undefined) => {
      const patchedIps = config?.GeoIPOverrides
        ? Object.values(config.GeoIPOverrides).map((x: GeoIPOverride) => x.ip)
        : [];
      return ipErrors
        ?.filter((x) => !patchedIps.includes(x.metric?.network))
        ?.sort((a, b) => parseInt(b.value[1]) - parseInt(a.value[1]));
    },
    [config?.GeoIPOverrides]
  );

  // State for the modal form to add new IP overrides
  const [openForm, setOpenForm] = useState(false);
  const [ip, setIp] = useState('');
  const [geoIpOverrides, setGeoIpOverrides] = useState<
    Record<string, GeoIPOverride>
  >({});
  const onFormSubmit = useCallback((x: GeoIPOverride) => {
    setGeoIpOverrides((p) => {
      return { ...p, [x.ip]: x };
    });
    setOpenForm(false);
  }, []);
  const submitModifiedOverrides = useCallback(async () => {
    const overrides = [
      ...Object.values(config?.GeoIPOverrides || []),
      ...Object.values(geoIpOverrides),
    ];
    const value = await alertOnError(
      async () => submitConfigChange({ GeoIPOverrides: overrides }),
      'Could not submit IP patches',
      dispatch
    );
    if (value !== undefined) {
      mutate();
      setGeoIpOverrides({});
    }
  }, [geoIpOverrides, config?.GeoIPOverrides, dispatch, mutate]);

  // Determine the IPs to display
  const ipErrors = useMemo(() => {
    return transformIpErrors(
      activeView == 'server' ? serverIpErrors : clientIpErrors
    );
  }, [transformIpErrors, activeView, clientIpErrors, serverIpErrors]);

  return (
    <>
      <Typography variant={'h4'} pb={2}>
        Un-located Networks
        {isValidating && <CircularProgress size={'24px'} sx={{ ml: 1 }} />}
      </Typography>
      <Paper sx={{ overflow: 'hidden' }}>
        <GeoIpErrorTable
          ipErrors={ipErrors}
          setIp={setIp}
          setOpenForm={setOpenForm}
          geoIpOverrides={geoIpOverrides}
        />
        <Box
          display={'flex'}
          flexDirection={'row'}
          justifyContent={'space-between'}
          alignItems={'center'}
        >
          <ButtonGroup sx={{ m: 1 }} variant={'outlined'}>
            <Button
              variant={activeView === 'server' ? 'contained' : 'outlined'}
              onClick={() => setActiveView('server')}
            >
              Server IPs
            </Button>
            <Button
              variant={activeView === 'client' ? 'contained' : 'outlined'}
              onClick={() => setActiveView('client')}
            >
              Client IPs
            </Button>
          </ButtonGroup>
          {Object.keys(geoIpOverrides).length > 0 && (
            <Button
              sx={{ m: 1 }}
              variant={'outlined'}
              onClick={submitModifiedOverrides}
            >
              Submit IP Patches ({Object.keys(geoIpOverrides).length})
            </Button>
          )}
        </Box>
      </Paper>
      <ObjectModal
        name={'Locate Network IP'}
        handleClose={() => setOpenForm(!open)}
        open={openForm}
      >
        <GeoIPOverrideForm
          value={{ ip: ip, coordinate: { lat: '37', long: '20' } }}
          onSubmit={onFormSubmit}
        />
      </ObjectModal>
    </>
  );
};

export default GeoIpErrorDisplay;
