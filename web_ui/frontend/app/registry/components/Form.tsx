import { Box, Button, Alert } from '@mui/material';
import React, {
  useEffect,
  useState,
  Dispatch,
  SetStateAction,
  useContext,
} from 'react';
import useSWR from 'swr';

import { Namespace } from '@/index';
import CustomRegistrationField from '@/app/registry/components/CustomRegistrationField/index';
import {
  calculateKeys,
  deleteKey,
  getValue,
  populateKey,
  submitNamespaceForm,
} from '@/app/registry/components/util';
import { CustomRegistrationFieldProps } from './CustomRegistrationField';
import { alertOnError, getErrorMessage } from '@/helpers/util';
import { optionsNamespaceRegistrationFields } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';

interface FormProps {
  namespace?: Namespace;
  onSubmit: (data: Partial<Namespace>) => Promise<void>;
}

const onChange = (
  name: string,
  value: string | number | boolean | null,
  setData: Dispatch<SetStateAction<Partial<Namespace | undefined>>>
) => {
  setData((prevData) => {
    // If the value is undefined delete this key from the data dictionary
    if (value === undefined) {
      let newData = structuredClone(prevData);
      deleteKey(newData, calculateKeys(name));
      return newData;
    }

    // Otherwise populate the key in the data dictionary
    let newData = structuredClone(prevData);
    populateKey(newData, calculateKeys(name), value);
    return newData;
  });
};

const Form = ({ namespace, onSubmit }: FormProps) => {
  const dispatch = useContext(AlertDispatchContext);

  const [data, setData] = useState<Partial<Namespace> | undefined>(
    namespace || {}
  );

  const { data: fields, error } = useSWR<
    Omit<CustomRegistrationFieldProps, 'onChange'>[] | undefined
  >(
    'optionsNamespaceRegistrationFields',
    async () =>
      await alertOnError(
        optionsNamespaceRegistrationFields,
        "Couldn't fetch registration fields",
        dispatch
      ),
    { fallbackData: [] }
  );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();

        if (!data) {
          return;
        }
        onSubmit(data);
      }}
    >
      {error && (
        <Alert severity={'error'}>{error.message}; Retry is automatic.</Alert>
      )}
      {fields &&
        fields.map((field, index) => {
          return (
            <Box key={field.name} pt={index == 0 ? 0 : 2}>
              <CustomRegistrationField
                onChange={(value: string | number | boolean | null) =>
                  onChange(field.name, value, setData)
                }
                value={getValue(data, calculateKeys(field.name))}
                {...field}
              />
            </Box>
          );
        })}
      <Box pt={2}>
        <Button type={'submit'} variant={'contained'}>
          Submit
        </Button>
      </Box>
    </form>
  );
};

export default Form;
