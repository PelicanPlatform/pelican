import React, { useMemo, useCallback } from 'react';
import { DateTimePicker, LocalizationProvider } from '@mui/x-date-pickers';
import { DateTime } from 'luxon';
import 'chartjs-adapter-luxon';
import { AdapterLuxon } from '@mui/x-date-pickers/AdapterLuxon';

import { createId, buildPatch } from '../util';

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

  const localValue = useMemo(() => DateTime.fromSeconds(value), [value]);
  const handleOnChange = useCallback(
    (value: DateTime | null) => {
      if (value === null) {
        return;
      }

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
