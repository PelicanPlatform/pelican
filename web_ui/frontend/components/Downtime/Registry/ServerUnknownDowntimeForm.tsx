'use client';

import {
  Autocomplete,
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  MenuItem,
  Select,
  TextField,
} from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers';
import { mutate } from 'swr';
import { DateTime } from 'luxon';
import { Dispatch, useContext, useEffect, useMemo, useState } from 'react';
import {
  DowntimeClass,
  DowntimeGet,
  DowntimeRegistryPost,
  DowntimeSeverity,
} from '@/types';
import {
  DowntimeSeverities,
  ServerDowntimeKey,
} from '@/components/Downtime';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import { alertOnError } from '@/helpers/util';
import {
  deleteDowntime,
  getNamespaces,
  postDowntime,
  putDowntime,
} from '@/helpers/api';
import {
  AlertDispatchContext,
  AlertReducerAction,
} from '@/components/AlertProvider';
import { Delete } from '@mui/icons-material';
import FormHelperText from '@mui/material/FormHelperText';
import { RegistryNamespace } from '@/index';
import useApiSWR from '@/hooks/useApiSWR';
import extendNamespace from '@/helpers/Registry/namespaceToServer';
import { NamespaceIcon } from '@/components';
import getUtcOffsetString from '@/helpers/getUtcOffsetString';

interface DowntimeFormProps {
  downtime: Partial<DowntimeGet>;
  onSuccess?: (downtime: DowntimeRegistryPost) => void;
}

const ServerUnknownDowntimeForm = ({
  downtime: inputDowntime,
  onSuccess,
}: DowntimeFormProps) => {
  const dispatch = useContext(AlertDispatchContext);

  const [downtime, setDowntime] = useState<DowntimeRegistryPost>({
    ...defaultDowntime,
    ...inputDowntime,
  });

  const id = 'id' in inputDowntime ? inputDowntime.id : undefined;
  const endless = useMemo(() => downtime.endTime === -1, [downtime.endTime]);

  // Get the cache and origin prefixes to key the downtimes for the director
  const { data: namespaces } = useApiSWR<RegistryNamespace[]>(
    'Could not fetch Origins and Caches to populate downtime form',
    'getNamespaces-TODO-update-this-key-to-share-cache',
    getNamespaces
  );
  const servers = useMemo(() => {
    return (namespaces || [])
      .map(extendNamespace)
      .filter(
        (x) =>
          (x.type === 'origin' || x.type === 'cache') &&
          x.admin_metadata.status === 'Approved'
      )
      .sort((a, b) =>
        (a?.adjustedPrefix || '') > (b?.adjustedPrefix || '') ? 1 : -1
      );
  }, [namespaces]);

  // Set a default prefix on registry
  useEffect(() => {
    if (servers.length > 0 && downtime.serverName === '') {
      setDowntime({ ...downtime, serverName: servers[0].prefix });
    }
  }, [servers, setDowntime, downtime]);

  // Keep the downtime class updated based on the 24 hours requirement
  useEffect(() => {
    if(DateTime.fromMillis(downtime.startTime) < DateTime.now().plus({hours: 24})){
      // If the start time is less than 24 hours from now, we need to set the class to unscheduled
      if(downtime.class !== 'UNSCHEDULED'){
        setDowntime({...downtime, class: 'UNSCHEDULED'});
      }
    } else {
      // If the start time is more than 24 hours from now, we need to
      if(downtime.class !== 'SCHEDULED'){
        setDowntime({...downtime, class: 'SCHEDULED'});
      }
    }
  }, [downtime, setDowntime]);

  // If the starttime is updated, before the endtime, adjust the endtime to be 1 day after the starttime
  useEffect(() => {
    if(downtime.endTime !== -1 && DateTime.fromMillis(downtime.endTime) <= DateTime.fromMillis(downtime.startTime)){
      setDowntime({...downtime, endTime: DateTime.fromMillis(downtime.startTime).plus({days: 1}).toMillis()});
    }
  }, [downtime, setDowntime]);

  return (
    <Box>
      <Box mt={2}>
        <Autocomplete
          options={servers}
          getOptionLabel={(servers) => servers?.adjustedPrefix || 'Error'}
          isOptionEqualToValue={(servers, value) =>
            servers?.adjustedPrefix === value?.adjustedPrefix
          }
          value={
            servers.filter((x) => x.prefix == downtime.serverName)[0] ||
            servers[0]
          }
          onChange={(e, v) => {
            if (!v) return;
            setDowntime({ ...downtime, serverName: v.prefix });
          }}
          renderInput={(params) => (
            <TextField {...params} label='Server' variant='outlined' required />
          )}
          renderOption={(params, option) => (
            <Box component='li' {...params} key={params.key}>
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  width: '100%',
                }}
              >
                <Box display={'flex'}>
                  {option.adjustedPrefix || option.prefix}
                </Box>
                <Box display={'flex'}>
                  <NamespaceIcon serverType={option.type} />
                </Box>
              </Box>
            </Box>
          )}
        />
      </Box>
      <Box mt={2}>
        <DateTimePicker
          label={`Start Time (${getUtcOffsetString()})`}
          value={DateTime.fromMillis(downtime.startTime)}
          onChange={(v) =>
            setDowntime({ ...downtime, startTime: v?.toMillis() || 0 })
          }
        />
      </Box>
      <Box mt={2}>
        <DateTimePicker
          label={`End Time (${getUtcOffsetString()})`}
          disabled={endless}
          value={DateTime.fromMillis(downtime.endTime)}
          onChange={(v) =>
            setDowntime({ ...downtime, endTime: v?.toMillis() || 0 })
          }
        />
      </Box>
      <Box>
        <FormControlLabel
          control={
            <Checkbox
              checked={endless}
              onChange={() => {
                if (endless) {
                  setDowntime({ ...downtime, endTime: Date.now() });
                } else {
                  setDowntime({ ...downtime, endTime: -1 });
                }
              }}
            />
          }
          label='Unknown Endtime'
        />
      </Box>
      <Box mt={2}>
        <FormControl fullWidth>
          <InputLabel id='severity'>Severity</InputLabel>
          <Select
            variant={'outlined'}
            labelId={'severity'}
            label={'Severity'}
            value={downtime?.severity}
            onChange={(e) =>
              setDowntime({
                ...downtime,
                severity: e.target.value as DowntimeSeverity,
              })
            }
          >
            {DowntimeSeverities.map((severity) => (
              <MenuItem key={severity} value={severity}>
                {severity}
              </MenuItem>
            ))}
          </Select>
          <FormHelperText>How much of the resource is affected</FormHelperText>
        </FormControl>
      </Box>
      <Box pt={2}>
        <TextField
          fullWidth
          multiline
          label={'Description'}
          variant={'outlined'}
          value={downtime?.description}
          onChange={(e) =>
            setDowntime({ ...downtime, description: e.target.value })
          }
          helperText={'The reason and/or impact of the outage'}
        />
      </Box>
      <Box
        pt={2}
        display={'flex'}
        flexDirection={'row'}
        justifyContent={'space-between'}
      >
        <Button
          variant={'contained'}
          onClick={async () => {
            const r = await submitDowntime(downtime, dispatch, id);

            // If there is a response and it is not undefined, then we can assume it was successful
            if (r) {
              await mutate(ServerDowntimeKey);
              onSuccess && onSuccess(downtime);
            }
          }}
        >
          Submit
        </Button>
        {id && (
          <Button
            startIcon={<Delete />}
            color={'error'}
            variant={'outlined'}
            onClick={async () => {
              const r = await alertOnError(
                () => deleteDowntime(id),
                'Error deleting Downtime with ID: ' + id,
                dispatch
              );
              if (r) {
                await mutate(ServerDowntimeKey);
                onSuccess && onSuccess(downtime);
              }
            }}
          >
            Delete Downtime
          </Button>
        )}
      </Box>
    </Box>
  );
};

/**
 * Submit a new downtime with error handling
 */
const submitDowntime = async (
  downtime: DowntimeRegistryPost,
  dispatch: Dispatch<AlertReducerAction>,
  id?: string
) => {
  if (id !== undefined) {
    return await alertOnError(
      () => putDowntime(id, downtime),
      'Error updating Downtime with ID: ' + id,
      dispatch
    );
  } else {
    return await alertOnError(
      () => postDowntime(downtime),
      'Error creating a new Downtime',
      dispatch
    );
  }
};

const namespacesToRegistryServers = (
  namespaces: RegistryNamespace[]
): string[] => {
  const originsAndCaches = namespaces.filter(
    (n) => n.prefix.startsWith('/origin') || n.prefix.startsWith('/cache')
  );

  // Pull the prefixes out of the namespaces
  return originsAndCaches.map((n) => n.prefix);
};

const defaultDowntime = {
  serverName:  '',
  startTime: DateTime.now().toMillis(),
  endTime: DateTime.now().plus({days: 1}).toMillis(),
  description: '',
  severity: 'Outage (completely inaccessible)' as DowntimeSeverity,
  class: 'SCHEDULED' as DowntimeClass,
};

export default ServerUnknownDowntimeForm;
