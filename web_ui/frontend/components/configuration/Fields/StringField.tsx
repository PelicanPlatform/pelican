import { TextField } from '@mui/material';
import React, { useEffect, useMemo } from 'react';

import { createId } from '../util';

export type StringFieldProps = {
  name: string;
  value: string;
  focused?: boolean;
  onChange: (a: string) => void;
  verify?: (a: string) => string | undefined;
};

const StringField = ({
  onChange,
  name,
  value,
  focused,
  verify,
}: StringFieldProps) => {
  const id = useMemo(() => createId(name), [name]);

  // Hold a buffer value so that you can type freely without saving an invalid state
  const [bufferValue, setBufferValue] = React.useState(value);
  useEffect(() => {
    setBufferValue(value);
  }, [value]);

  const error = useMemo(
    () => (verify ? verify(bufferValue) : undefined),
    [bufferValue, verify]
  );

  return (
    <TextField
      fullWidth
      size='small'
      id={id}
      label={name}
      name={name.toLowerCase()}
      variant={'outlined'}
      focused={focused}
      value={bufferValue}
      onChange={(e) => {
        setBufferValue(e.target.value);

        // If there is a verification function then make sure it passes
        if (verify && verify(e.target.value) !== undefined) {
          return;
        }

        // If the verification passes then update the value as a patch
        onChange(e.target.value);
      }}
      helperText={error}
      error={error !== undefined}
    />
  );
};

export default StringField;
