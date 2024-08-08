import React, { MouseEventHandler, useCallback } from 'react';
import { Box, Button, TextField } from '@mui/material';

import { FormProps, Option, StringField } from '@/components/configuration';

const verifyForm = (x: Option) => {
  return x.id != '' && x.name != '';
};

const createDefaultOption = (): Option => {
  return {
    id: '',
    name: '',
  };
};

const OptionForm = ({ onSubmit, value }: FormProps<Option>) => {
  const [option, setOption] = React.useState<Option>(
    value || createDefaultOption()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(option)) {
      return;
    }

    onSubmit(option);
  }, [option]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'ID'}
          onChange={(e) => setOption({ ...option, id: e })}
          value={option.id}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Name'}
          onChange={(e) => setOption({ ...option, name: e })}
          value={option.name}
        />
      </Box>
      <Button onClick={submitHandler}>Submit</Button>
    </>
  );
};

export default OptionForm;
