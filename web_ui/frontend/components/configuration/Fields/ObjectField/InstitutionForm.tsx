import { Institution, StringField } from '@/components/configuration';
import React, { useCallback } from 'react';
import { Box, Button, TextField } from '@mui/material';

import { FormProps, ModalProps } from '@/components/configuration';
import { String } from 'ts-toolbelt';

const verifyForm = (x: Institution) => {
  return x.id != '' && x.name != '';
};

const createDefaultInstitution = (): Institution => {
  return {
    id: '',
    name: '',
  };
};

const InstitutionForm = ({ onSubmit, value }: FormProps<Institution>) => {
  const [institution, setInstitution] = React.useState<Institution>(
    value || createDefaultInstitution()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(institution)) {
      return;
    }
    onSubmit(institution);
  }, [institution]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'Name'}
          onChange={(e) => setInstitution({ ...institution, name: e })}
          value={institution.name}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'ID'}
          onChange={(e) => setInstitution({ ...institution, id: e })}
          value={institution?.id}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default InstitutionForm;
