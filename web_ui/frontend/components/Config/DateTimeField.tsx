import { DateTimePicker, LocalizationProvider } from '@mui/x-date-pickers';
import React, {
  useMemo,
  useCallback,
  SetStateAction,
  ChangeEvent,
} from 'react';

import { ParameterInputProps } from '@/components/Config/index.d';
import { createId, buildPatch } from './util';
import { DateTime } from 'luxon';
import 'chartjs-adapter-luxon';
import { AdapterLuxon } from '@mui/x-date-pickers/AdapterLuxon';

export type DateTimePickerFieldProps = {
  name: string;
  value: number;
  onChange: (a: number) => void;
  verify?: (a: DateTime | null) => string;
};

const DateTimeField = ({
  onChange,
  name,
  value,
  verify,
}: DateTimePickerFieldProps) => {
  const id = useMemo(() => createId(name), [name]);

  const [localValue, setLocalValue] = React.useState<DateTime | null>(
    value ? DateTime.fromSeconds(value) : null
  );

  const handleOnChange = useCallback(
    (value: DateTime | null) => {
      if (value === null) {
        return;
      }

      setLocalValue(value);

      onChange(value.toSeconds());
    },
    [onChange]
  );

  return (
    <LocalizationProvider dateAdapter={AdapterLuxon}>
      <DateTimePicker
        label={name}
        value={localValue}
        onChange={handleOnChange}
      />
    </LocalizationProvider>
  );
};

export default DateTimeField;
