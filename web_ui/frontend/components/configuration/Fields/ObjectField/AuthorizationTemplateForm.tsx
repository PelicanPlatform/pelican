import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import {
  Action,
  AuthorizationTemplate,
  FormProps,
  MultiSelectField,
  StringField,
  StringSliceField,
} from '@/components/configuration';

const verifyForm = (x: AuthorizationTemplate) => {
  return x.prefix != '' && x.actions.length > 0;
};

const createDefaultAuthorizationTemplate = (): AuthorizationTemplate => {
  return {
    prefix: '',
    actions: [],
    users: [],
    groups: [],
    'group_regexes': [],
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
  }, [authorizationTemplate, onSubmit]);

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
      <Box mb={2}>
        <StringSliceField
          name={'Users (Optional)'}
          value={authorizationTemplate.users || []}
          onChange={(e) =>
              setAuthorizationTemplate({ ...authorizationTemplate, users: e })
          }
        />
      </Box>
      <Box mb={2}>
        <StringSliceField
          name={'Groups (Optional)'}
          value={authorizationTemplate.groups || []}
          onChange={(e) =>
            setAuthorizationTemplate({ ...authorizationTemplate, groups: e })
          }
        />
      </Box>
      <Box mb={2}>
        <StringSliceField
          name={'Group Regexes (Optional)'}
          value={authorizationTemplate['group_regexes'] || []}
          onChange={(e) =>
            setAuthorizationTemplate({ ...authorizationTemplate, group_regexes: e })
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
