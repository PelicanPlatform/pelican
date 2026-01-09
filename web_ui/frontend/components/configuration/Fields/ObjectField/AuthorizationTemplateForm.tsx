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
import useApiSWR from "@/hooks/useApiSWR";
import { User, Group } from '@/types';
import AutocompleteField from "@/components/configuration/Fields/AutocompleteField";

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

  const {data: users} = useApiSWR<User[]>(
    "Could not fetch users",
    "getUsers",
    async () => fetch('/api/v1.0/users')
  )

  const {data: groups} = useApiSWR<Group[]>(
    "Could not fetch groups",
    "getGroups",
    async () => fetch('/api/v1.0/groups')
  )

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
        <AutocompleteField<string>
          name={'Users (Optional)'}
          onChange={(e) =>
            setAuthorizationTemplate({ ...authorizationTemplate, users: e })
          }
          value={authorizationTemplate.users || []}
          possibleValues={users ? users.map((u) => u.username) : []}
          freeSolo={true}
        />
      </Box>
      <Box mb={2}>
        <AutocompleteField<string>
          name={'Groups (Optional)'}
          onChange={(e) =>
            setAuthorizationTemplate({ ...authorizationTemplate, groups: e })
          }
          value={authorizationTemplate.groups || []}
          possibleValues={groups ? groups.map((g) => g.name) : []}
          freeSolo={true}
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
