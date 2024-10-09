import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from '@mui/material';
import React, {
  useMemo,
  useCallback,
  SetStateAction,
  ChangeEvent,
  useState,
  useEffect,
} from 'react';

import {
  ParameterInputProps,
  Duration,
  DurationString,
} from '@/components/configuration';
import { createId, buildPatch } from '../util';

export type DurationFieldProps = {
  name: string;
  value: number;
  focused?: boolean;
  onChange: (x: number) => void;
};

const DurationField = ({
  onChange,
  name,
  value,
  focused,
}: DurationFieldProps) => {
  const id = useMemo(() => createId(name), [name]);

  const [bufferValue, setBufferValue] = useState<string>(
    nanosecondsToDurationString(value)
  );

  useEffect(() => {
    setBufferValue(nanosecondsToDurationString(value));
  }, [value]);

  const error = useMemo(() => {
    if (!verifyDuration(bufferValue)) {
      return 'Invalid duration format';
    }
    return undefined;
  }, [bufferValue]);

  const handleOnChange = useCallback(
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      // Ignore the change if not valid
      if (error !== undefined) {
        return;
      }

      // Otherwise send it up
      const v = event.target.value as DurationString;
      const durationInNanoseconds = durationStringToNanoseconds(v);
      onChange(durationInNanoseconds);
    },
    [onChange, error]
  );

  return (
    <TextField
      fullWidth
      size='small'
      id={id}
      label={name}
      variant={'outlined'}
      focused={focused}
      value={bufferValue}
      onChange={(e) => setBufferValue(e.target.value)}
      onBlur={handleOnChange}
      error={error !== undefined}
      helperText={error}
    />
  );
};

/**
 * Convert a duration string to nanoseconds
 */
const durationStringToNanoseconds = (value: DurationString): number => {
  const number = parseFloat(value.match(/[^a-z]*/)?.[0] || '0');
  const unit = value.replace(/[^a-z]/g, '');

  let nanoseconds;
  switch (unit) {
    case 'ns':
      nanoseconds = number;
      break;
    case 'us':
    case 'µs':
      nanoseconds = number * 1000;
      break;
    case 'ms':
      nanoseconds = number * 1000000;
      break;
    case 's':
      nanoseconds = number * 1000000000;
      break;
    case 'm':
      nanoseconds = number * 60000000000;
      break;
    case 'h':
      nanoseconds = number * 3600000000000;
      break;
    default:
      nanoseconds = number;
  }

  return Math.ceil(nanoseconds);
};

/**
 * Convert nanoseconds to a duration string
 * @param value
 */
const nanosecondsToDurationString = (value: number): DurationString => {
  let durationString;
  if (value < 1000) {
    durationString = value + 'ns';
  } else if (value < 1000000) {
    durationString = value / 1000 + 'us';
  } else if (value < 1000000000) {
    durationString = value / 1000000 + 'ms';
  } else if (value < 60000000000) {
    durationString = value / 1000000000 + 's';
  } else if (value < 3600000000000) {
    durationString = value / 60000000000 + 'm';
  } else {
    durationString = value / 3600000000000 + 'h';
  }

  return durationString as DurationString;
};

/**
 * Verify if the duration is in the correct format
 * @param value
 */
const verifyDuration = (value: string): boolean => {
  const regex = new RegExp('^[0-9]*\\.?[0-9]*(?:ns|us|µs|ms|s|m|h|.)$');
  return regex.test(value);
};

export default DurationField;
