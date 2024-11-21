import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Checkbox,
} from '@mui/material';
import React, { ChangeEvent, ReactNode, SyntheticEvent, useMemo } from 'react';

import { createId } from '@/components/configuration/util';
import FormHelperText from '@mui/material/FormHelperText';
import type { BaseCustomRegistrationFieldProps } from './index';

const BooleanField = ({
  onChange,
  displayed_name,
  name,
  required,
  description,
  value,
}: BaseCustomRegistrationFieldProps<boolean>) => {
  const id = useMemo(() => createId(name), [name]);
  const labelId = useMemo(() => `${id}-label`, [id]);

  return (
    <FormControl fullWidth size={'small'}>
      <InputLabel id={labelId}>{displayed_name}</InputLabel>
      <Select
        size='small'
        labelId={labelId}
        id={id}
        label={displayed_name}
        name={name}
        required={required}
        value={value == undefined ? '' : value.toString()}
        onChange={(e) => onChange(e.target.value === 'true')}
      >
        <MenuItem value={'true'}>True</MenuItem>
        <MenuItem value={'false'}>False</MenuItem>
      </Select>
      {description && <FormHelperText>{description}</FormHelperText>}
    </FormControl>
  );
};

export default BooleanField;
export { BooleanField };
