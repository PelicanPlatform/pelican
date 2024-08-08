import React, { useCallback } from 'react';
import { Box, Button, TextField } from '@mui/material';

import {
  FormProps,
  OIDCAuthenticationRequirement, StringField,
} from '@/components/configuration';
import { String } from 'ts-toolbelt';

const verifyForm = (x: OIDCAuthenticationRequirement) => {
  return x.claim != '' && x.value != '';
};

const createDefaultOIDCAuthenticationRequirement =
  (): OIDCAuthenticationRequirement => {
    return {
      claim: '',
      value: '',
    };
  };

const OIDCAuthenticationRequirementForm = ({
  onSubmit,
  value,
}: FormProps<OIDCAuthenticationRequirement>) => {
  const [authReq, setAuthReq] = React.useState<OIDCAuthenticationRequirement>(
    value || createDefaultOIDCAuthenticationRequirement()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(authReq)) {
      return;
    }
    onSubmit(authReq);
  }, [authReq]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={"Claim"}
          value={authReq.claim}
          onChange={(e) => setAuthReq({ ...authReq, claim: e })}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={"Value"}
          value={authReq.value}
          onChange={(e) => setAuthReq({ ...authReq, value: e })}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default OIDCAuthenticationRequirementForm;
