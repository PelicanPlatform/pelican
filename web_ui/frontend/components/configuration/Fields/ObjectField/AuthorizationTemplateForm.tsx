import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import {
  FormProps,
  Action,
  AuthorizationTemplate,
} from '@/components/configuration';
import { StringField, MultiSelectField } from '@/components/configuration';

const verifyForm = (x: AuthorizationTemplate) => {
  return x.prefix != '' && x.actions.length > 0;
};

const createDefaultAuthorizationTemplate = (): AuthorizationTemplate => {
  return {
    prefix: '',
    actions: [],
  };
};

const AuthorizationTemplateForm = ({
  onSubmit,
  value,
}: FormProps<AuthorizationTemplate>) => {
  const [authorizationTemplate, setAuthorizationTemplate] =
    React.useState<AuthorizationTemplate>(
      value || createDefaultAuthorizationTemplate()
    );

  const submitHandler = useCallback(() => {
    if (!verifyForm(authorizationTemplate)) {
      return;
    }
    onSubmit(authorizationTemplate);
  }, [authorizationTemplate]);

  return (
    <>
      <Box my={2}>
        <MultiSelectField<Action>
          name={'Actions'}
          onChange={(e) =>
            setAuthorizationTemplate({ ...authorizationTemplate, actions: e })
          }
          value={authorizationTemplate.actions}
          possibleValues={['read', 'modify', 'create']}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Prefix'}
          value={authorizationTemplate.prefix}
          onChange={(e) =>
            setAuthorizationTemplate({ ...authorizationTemplate, prefix: e })
          }
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default AuthorizationTemplateForm;
