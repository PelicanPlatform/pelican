'use client';

import {
  TextField,
  Button,
  Select,
  Box,
  MenuItem,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers';
import { mutate } from 'swr';
import { DateTime } from 'luxon';
import {Dispatch, useContext, useEffect, useMemo, useState} from 'react';
import {
  DowntimeClass,
  DowntimeGet,
  DowntimePost,
  DowntimeRegistryPost,
  DowntimeSeverity,
} from '@/types';
import { DowntimeClasses, DowntimeSeverities } from '@/components/Downtime';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import { alertOnError } from '@/helpers/util';
import {
  deleteDowntime,
  postDowntime,
  putDowntime,
  getNamespaces,
} from '@/helpers/api';
import {
  AlertDispatchContext,
  AlertReducerAction,
} from '@/components/AlertProvider';
import { ServerDowntimeKey } from '@/components/Downtime';
import { Delete } from '@mui/icons-material';
import FormHelperText from '@mui/material/FormHelperText';
import { useSearchParams } from 'next/navigation';
import { RegistryNamespace } from '@/index';
import useApiSWR from '@/hooks/useApiSWR';

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
    serverName: inputDowntime.serverName ?? '',
    startTime: inputDowntime.startTime ?? Date.now(),
    endTime: inputDowntime.endTime ?? Date.now(),
    description: inputDowntime.description ?? '',
    severity: inputDowntime.severity ?? defaultDowntime.severity,
    class: inputDowntime.class ?? defaultDowntime.class,
  });

  const id = 'id' in inputDowntime ? inputDowntime.id : undefined;
  const endless = useMemo(() => downtime.endTime === -1, [downtime.endTime]);

  // Get the cache and origin prefixes to key the downtimes for the director
  const { data: namespaces } = useApiSWR<RegistryNamespace[]>(
    'Could not fetch Origins and Caches to populate downtime form',
    'getNamespaces',
    getNamespaces
  );
  const prefixes = useMemo(
    () => namespacesToOriginAndCachePrefixes(namespaces || []),
    [namespaces]
  );

  // Set a default prefix on registry
  useEffect(() => {
    if(prefixes.length > 0 && downtime.serverName === '') {
      setDowntime({ ...downtime, serverName: prefixes[0] });
    }
  }, [prefixes, setDowntime, downtime])

  return (
    <Box>
      <Box mt={2}>
        <FormControl fullWidth>
          <InputLabel id='server-prefix-label'>Server Prefix</InputLabel>
          <Select
            required
            labelId='server-prefix-label'
            id='server-prefix'
            value={downtime.serverName}
            label='Server Prefix'
            onChange={(e) => {
              setDowntime({ ...downtime, serverName: e.target.value });
            }}
          >
            {prefixes.map((prefix) => (
              <MenuItem
                key={prefix}
                value={prefix}
                selected={prefix === downtime.serverName}
              >
                {prefix}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>
      <Box mt={2}>
        <DateTimePicker
          label={'Start Time'}
          value={DateTime.fromMillis(downtime.startTime)}
          onChange={(v) =>
            setDowntime({ ...downtime, startTime: v?.toMillis() || 0 })
          }
        />
      </Box>
      <Box mt={2}>
        <DateTimePicker
          label={'End Time'}
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
      <Box mt={2}>
        <FormControl fullWidth>
          <InputLabel id='class'>Scheduled</InputLabel>
          <Select
            variant={'outlined'}
            labelId={'class'}
            label={'class'}
            value={downtime?.class}
            onChange={(e) =>
              setDowntime({
                ...downtime,
                class: e.target.value as DowntimeClass,
              })
            }
          >
            {DowntimeClasses.map((downtimeClass) => (
              <MenuItem key={downtimeClass} value={downtimeClass}>
                {downtimeClass}
              </MenuItem>
            ))}
          </Select>
          <FormHelperText>
            SCHEDULED - Registered at least 24 hours in advance
            <br />
            UNSCHEDULED - Registered less than 24 hours in advance
          </FormHelperText>
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

const namespacesToOriginAndCachePrefixes = (
  namespaces: RegistryNamespace[]
): string[] => {
  const originsAndCaches = namespaces.filter(
    (n) => n.prefix.startsWith('/origin') || n.prefix.startsWith('/cache')
  );

  // Pull the prefixes out of the namespaces
  return originsAndCaches.map((n) => n.prefix);
};

const defaultDowntime = {
  severity: 'Outage (completely inaccessible)' as DowntimeSeverity,
  class: 'SCHEDULED' as DowntimeClass,
};

export default ServerUnknownDowntimeForm;
