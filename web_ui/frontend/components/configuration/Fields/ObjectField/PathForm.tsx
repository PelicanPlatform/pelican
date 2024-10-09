import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import {
  FormProps,
  Path,
  StringField,
  BooleanField,
} from '@/components/configuration';

const verifyForm = (x: Path) => {
  return x.path != '';
};

const createDefaultPath = (): Path => {
  return {
    path: '',
    recursive: true,
  };
};

const PathForm = ({ onSubmit, value }: FormProps<Path>) => {
  const [path, setPath] = React.useState<Path>(value || createDefaultPath());

  const submitHandler = useCallback(() => {
    if (!verifyForm(path)) {
      return;
    }
    onSubmit(path);
  }, [path]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'Path'}
          onChange={(e) => setPath({ ...path, path: e })}
          value={path.path}
        />
      </Box>
      <Box mb={2}>
        <BooleanField
          name={'Name'}
          onChange={(e) => setPath({ ...path, recursive: e })}
          value={path.recursive}
        />
      </Box>
      <Button onClick={submitHandler}>Submit</Button>
    </>
  );
};

export default PathForm;
