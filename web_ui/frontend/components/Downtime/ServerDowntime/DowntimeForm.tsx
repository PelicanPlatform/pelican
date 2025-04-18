'use client';

import {
  TextField,
  Button,
  Select,
  Box,
  Typography,
  MenuItem,
  IconButton,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers';
import { mutate } from 'swr';
import { DateTime } from 'luxon';
import { Dispatch, useContext, useMemo, useState } from 'react';
import {
  DowntimeClass,
  DowntimeGet,
  DowntimePost,
  DowntimeSeverity,
} from '@/types';
import { DowntimeClasses, DowntimeSeverities } from '@/components/Downtime';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import { alertOnError } from '@/helpers/util';
import { deleteDowntime, postDowntime, putDowntime } from '@/helpers/api';
import {
  AlertDispatchContext,
  AlertReducerAction,
} from '@/components/AlertProvider';
import { ServerDowntimeKey } from '@/components/Downtime';
import { Delete } from '@mui/icons-material';
import FormHelperText from '@mui/material/FormHelperText';

interface DowntimeFormProps {
  downtime:
    | DowntimeGet
    | Omit<DowntimePost, 'severity' | 'class' | 'description'>;
  onSuccess?: (downtime: DowntimePost) => void;
}

const DowntimeForm = ({
  downtime: inputDowntime,
  onSuccess,
}: DowntimeFormProps) => {
  const dispatch = useContext(AlertDispatchContext);

  const id = 'id' in inputDowntime ? inputDowntime.id : undefined;

  const [downtime, setDowntime] = useState<DowntimePost>({
    startTime: inputDowntime.startTime,
    endTime: inputDowntime.endTime,
    description:
      'description' in inputDowntime ? inputDowntime.description : '',
    severity:
      'severity' in inputDowntime
        ? inputDowntime.severity
        : defaultDowntime.severity,
    class:
      'class' in inputDowntime ? inputDowntime.class : defaultDowntime.class,
  });

  const endless = useMemo(() => downtime.endTime === -1, [downtime.endTime]);

  console.log(endless, downtime);

  return (
    <Box>
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

const defaultDowntime = {
  severity:
    'Intermittent Outage (may be up for some of the time)' as DowntimeSeverity,
  class: 'SCHEDULED' as DowntimeClass,
};

export default DowntimeForm;
