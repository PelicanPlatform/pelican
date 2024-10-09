import {
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  SelectChangeEvent,
} from '@mui/material';
import React, { useMemo, useCallback } from 'react';

import { createId, buildPatch } from '../util';

export type BooleanFieldProps = {
  name: string;
  value: boolean;
  focused?: boolean;
  onChange: (value: boolean) => void;
};

const BooleanField = ({
  onChange,
  name,
  value,
  focused,
}: BooleanFieldProps) => {
  const id = useMemo(() => createId(name), [name]);
  const labelId = useMemo(() => `${id}-label`, [id]);

  return (
    <FormControl fullWidth focused={focused}>
      <InputLabel id={labelId}>{name}</InputLabel>
      <Select
        size='small'
        labelId={labelId}
        id={id}
        label={name}
        value={value ? 1 : 0}
        onChange={(e) => onChange(e.target.value === 1)}
      >
        <MenuItem value={1}>True</MenuItem>
        <MenuItem value={0}>False</MenuItem>
      </Select>
    </FormControl>
  );
};

export default BooleanField;
