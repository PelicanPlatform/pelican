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
} from 'react';

import {
  ParameterInputProps,
  Duration,
  DurationString,
} from '@/components/Config/index.d';
import { createId, buildPatch } from './util';

/**
 * Convert a duration string to nanoseconds
 */
const durationStringToNanoseconds = (value: DurationString): number => {
  const number = parseInt(value.replace(/\D/g, ''));
  const unit = value.replace(/[0-9]/g, '');
  switch (unit) {
    case 'ns':
      return number;
    case 'us':
    case 'µs':
      return number * 1000;
    case 'ms':
      return number * 1000000;
    case 's':
      return number * 1000000000;
    case 'm':
      return number * 60000000000;
    case 'h':
      return number * 3600000000000;
    default:
      return number;
  }
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
  const regex = new RegExp('^[0-9]+(?:ns|us|µs|ms|s|m|h|.)$');
  return regex.test(value);
};

export type DurationFieldProps = {
  name: string;
  value: number;
  onChange: (x: number) => void;
};

const DurationField = ({ onChange, name, value }: DurationFieldProps) => {
  const id = useMemo(() => createId(name), [name]);
  const stringValue = useMemo(() => {
    return nanosecondsToDurationString(value);
  }, [value]);

  const [localValue, setLocalValue] = React.useState<Duration>(stringValue);
  const [error, setError] = React.useState<string | undefined>(undefined);

  const handleOnChange = useCallback(
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      const v = event.target.value as DurationString;
      setLocalValue(v);

      if (!verifyDuration(event.target.value)) {
        setError('Invalid duration format');
      } else {
        setError(undefined);
        const durationInNanoseconds = durationStringToNanoseconds(v);
        onChange(durationInNanoseconds);
      }
    },
    [onChange]
  );

  return (
    <TextField
      fullWidth
      size='small'
      id={id}
      label={name}
      variant={'outlined'}
      focused={localValue != stringValue}
      value={localValue}
      onChange={handleOnChange}
      error={error !== undefined}
      helperText={error}
    />
  );
};

export default DurationField;
