import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import {
  Action,
  CustomRegistrationField,
  FieldType,
  Option,
  ObjectField,
  OptionForm,
  StringField,
  SelectField,
  BooleanField,
  FormProps,
} from '@/components/configuration';
import { Simulate } from 'react-dom/test-utils';
import submit = Simulate.submit;

const verifyForm = (x: CustomRegistrationField) => {
  return (
    x.name != '' &&
    (x.type as string) != '' &&
    x.description != '' &&
    x.validationurl != '' &&
    (x.type != 'enum' ||
      x.optionsurl != '' ||
      (x.options && x.options.length > 0))
  );
};

const createDefaultCustomRegistrationField = (): CustomRegistrationField => {
  return {
    name: '',
    type: '' as FieldType,
    description: '',
    required: false,
    validationurl: '',
    optionsurl: '',
    options: [],
  };
};

const CustomRegistrationFieldForm = ({
  onSubmit,
  value,
}: FormProps<CustomRegistrationField>) => {
  const [customRegistrationField, setCustomRegistrationField] =
    React.useState<CustomRegistrationField>(
      value || createDefaultCustomRegistrationField()
    );

  const submitHandler = useCallback(() => {
    if (!verifyForm(customRegistrationField)) {
      return;
    }

    // Convert empty strings to null when it is not required
    let objectCopy = structuredClone(customRegistrationField);
    if (customRegistrationField.validationurl == '') {
      delete objectCopy.validationurl;
    }
    if (customRegistrationField.optionsurl == '') {
      delete objectCopy.optionsurl;
    }
    if (
      customRegistrationField.options &&
      customRegistrationField.options.length == 0
    ) {
      delete objectCopy.options;
    }

    onSubmit(objectCopy);
  }, [customRegistrationField]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'Name'}
          onChange={(e) =>
            setCustomRegistrationField({ ...customRegistrationField, name: e })
          }
          value={customRegistrationField.name}
        />
      </Box>
      <Box mb={2}>
        <SelectField
          name={'Type'}
          onChange={(e) =>
            setCustomRegistrationField({
              ...customRegistrationField,
              type: e as FieldType,
            })
          }
          value={customRegistrationField.type}
          possibleValues={['string', 'int', 'bool', 'datetime', 'enum']}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Description'}
          onChange={(e) =>
            setCustomRegistrationField({
              ...customRegistrationField,
              description: e,
            })
          }
          value={customRegistrationField.description}
        />
      </Box>
      <Box mb={2}>
        <BooleanField
          name={'Required'}
          onChange={(e) =>
            setCustomRegistrationField({
              ...customRegistrationField,
              required: e,
            })
          }
          value={customRegistrationField.required}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Validation URL'}
          onChange={(e) =>
            setCustomRegistrationField({
              ...customRegistrationField,
              validationurl: e,
            })
          }
          value={customRegistrationField.validationurl || ''}
        />
      </Box>
      {customRegistrationField.type === 'enum' && (
        <Box mb={2}>
          <StringField
            name={'Option URL'}
            onChange={(e) =>
              setCustomRegistrationField({
                ...customRegistrationField,
                optionsurl: e,
              })
            }
            value={customRegistrationField.optionsurl || ''}
          />
        </Box>
      )}
      {customRegistrationField.type === 'enum' && (
        <Box mb={2}>
          <ObjectField
            name={'Options'}
            value={customRegistrationField.options || null}
            onChange={(e) =>
              setCustomRegistrationField({
                ...customRegistrationField,
                options: e,
              })
            }
            Form={OptionForm}
            keyGetter={(x) => x.id}
          />
        </Box>
      )}
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default CustomRegistrationFieldForm;
