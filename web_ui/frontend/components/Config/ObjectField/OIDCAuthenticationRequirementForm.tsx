import { OIDCAuthenticationRequirement } from '@/components/Config/index';
import React from 'react';
import { Box, Button, TextField } from '@mui/material';

import { FormProps } from '@/components/Config/ObjectField/ObjectField';

const verifyForm = (x: OIDCAuthenticationRequirement) => {
  return x.claim != '' && x.value != '';
};

const OIDCAuthenticationRequirementForm = ({
  onSubmit,
  value,
}: FormProps<OIDCAuthenticationRequirement>) => {
  const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const formData = new FormData(form);
    const value = {
      claim: formData.get('claim') as string,
      value: formData.get('value') as string,
    };

    if (!verifyForm(value)) {
      return;
    }

    onSubmit(value);
  };

  return (
    <form onSubmit={submitHandler}>
      <Box my={2}>
        <TextField
          fullWidth
          size='small'
          id={'claim'}
          name={'claim'}
          label={'Claim'}
          variant={'outlined'}
          defaultValue={value?.claim}
        />
      </Box>
      <Box mb={2}>
        <TextField
          fullWidth
          size='small'
          id={'value'}
          name={'value'}
          label={'Value'}
          variant={'outlined'}
          defaultValue={value?.value}
        />
      </Box>
      <Button type={'submit'}>Submit</Button>
    </form>
  );
};

export default OIDCAuthenticationRequirementForm;
