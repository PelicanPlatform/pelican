import { Action, AuthorizationTemplate } from '@/components/Config/index.d';
import React from 'react';
import { Box, Button } from '@mui/material';

import { FormProps } from '@/components/Config/ObjectField/ObjectField';
import { StringField } from '@/components/Config';
import MultiSelectField from '@/components/Config/MultiSelectField';

const verifyForm = (x: AuthorizationTemplate) => {
  return x.prefix != '' && x.actions.length > 0;
};

const AuthorizationTemplateForm = ({
  onSubmit,
  value,
}: FormProps<AuthorizationTemplate>) => {
  const [actions, setActions] = React.useState<Action[]>(value?.actions || []);
  const [prefix, setPrefix] = React.useState<string>(value?.prefix || '');

  const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const value = {
      actions: actions,
      prefix: prefix,
    };

    if (!verifyForm(value)) {
      return;
    }

    onSubmit(value);
  };

  return (
    <form onSubmit={submitHandler}>
      <Box my={2}>
        <MultiSelectField<Action>
          onChange={setActions}
          name={'Actions'}
          value={actions}
          possibleValues={['read', 'modify', 'create']}
        />
      </Box>
      <Box mb={2}>
        <StringField onChange={setPrefix} name={'Prefix'} value={prefix} />
      </Box>
      <Button type={'submit'}>Submit</Button>
    </form>
  );
};

export default AuthorizationTemplateForm;
