'use client';

import {
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
  DowntimePost,
  DowntimeRegistryPost,
  DowntimeSeverity,
} from '@/types';
import {
  DowntimeClasses,
  DowntimeSeverities,
  ServerDowntimeKey,
} from '@/components/Downtime';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import { alertOnError } from '@/helpers/util';
import { deleteDowntime, postDowntime, putDowntime } from '@/helpers/api';
import {
  AlertDispatchContext,
  AlertReducerAction,
} from '@/components/AlertProvider';
import { Delete } from '@mui/icons-material';
import FormHelperText from '@mui/material/FormHelperText';
import getUtcOffsetString from '@/helpers/getUtcOffsetString';
import { defaultDowntime } from '@/components/Downtime/constant';

interface DowntimeFormProps {
  downtime:
    | DowntimeGet
    | Partial<DowntimePost>
    | Omit<DowntimeRegistryPost, 'severity' | 'class' | 'description'>;
  onSuccess?: (downtime: DowntimePost) => void;
}

const DowntimeForm = ({
  downtime: inputDowntime,
  onSuccess,
}: DowntimeFormProps) => {
  const dispatch = useContext(AlertDispatchContext);

  const id = 'id' in inputDowntime ? inputDowntime.id : undefined;

  const [downtime, setDowntime] = useState<DowntimeRegistryPost>({
    ...defaultDowntime,
    ...inputDowntime,
  });

  const endless = useMemo(() => downtime.endTime === -1, [downtime.endTime]);

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
  downtime: DowntimePost,
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

export default DowntimeForm;
