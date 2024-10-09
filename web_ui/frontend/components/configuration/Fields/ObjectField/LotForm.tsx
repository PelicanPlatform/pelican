import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import { FormProps, Action, Lot, Path } from '@/components/configuration';
import {
  StringField,
  IntegerField,
  DateTimeField,
  ObjectField,
  PathForm,
} from '@/components/configuration';

const verifyForm = (x: Lot) => {
  return (
    x.lotname != '' &&
    x.owner != '' &&
    x.managementpolicyattrs.creationtime.value != 0 &&
    x.managementpolicyattrs.expirationtime.value != 0 &&
    x.managementpolicyattrs.deletiontime.value != 0
  );
};

const createDefaultLot = (): Lot => {
  return {
    lotname: '',
    owner: '',
    paths: [],
    managementpolicyattrs: {
      dedicatedgb: 0,
      opportunisticgb: 0,
      maxnumberobjects: {
        value: 0,
      },
      creationtime: {
        value: Date.now() / 1000,
      },
      expirationtime: {
        value: Date.now() / 1000,
      },
      deletiontime: {
        value: Date.now() / 1000,
      },
    },
  };
};

const LotForm = ({ onSubmit, value }: FormProps<Lot>) => {
  const [lot, setLot] = React.useState<Lot>(value || createDefaultLot());

  const submitHandler = useCallback(() => {
    if (!verifyForm(lot)) {
      return;
    }
    onSubmit(lot);
  }, [lot]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'LotName'}
          onChange={(e) => setLot({ ...lot, lotname: e })}
          value={lot.lotname}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Owner'}
          onChange={(e) => setLot({ ...lot, owner: e })}
          value={lot.owner}
        />
      </Box>
      <Box mb={2}>
        <ObjectField
          name={'Paths'}
          onChange={(e) => setLot({ ...lot, paths: e })}
          value={lot.paths}
          Form={PathForm}
          keyGetter={(x) => x.path}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'DedicatedGB'}
          onChange={(e) =>
            setLot({
              ...lot,
              managementpolicyattrs: {
                ...lot.managementpolicyattrs,
                dedicatedgb: e,
              },
            })
          }
          value={lot.managementpolicyattrs.dedicatedgb}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'OpportunisticGB'}
          onChange={(e) =>
            setLot({
              ...lot,
              managementpolicyattrs: {
                ...lot.managementpolicyattrs,
                opportunisticgb: e,
              },
            })
          }
          value={lot.managementpolicyattrs.opportunisticgb}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'MaxNumObjects'}
          onChange={(e) =>
            setLot({
              ...lot,
              managementpolicyattrs: {
                ...lot.managementpolicyattrs,
                maxnumberobjects: { value: e },
              },
            })
          }
          value={lot.managementpolicyattrs.maxnumberobjects.value}
        />
      </Box>
      <Box mb={2}>
        <DateTimeField
          name={'CreationTime'}
          onChange={(e) =>
            setLot({
              ...lot,
              managementpolicyattrs: {
                ...lot.managementpolicyattrs,
                creationtime: { value: e },
              },
            })
          }
          value={lot.managementpolicyattrs.creationtime.value}
        />
      </Box>
      <Box mb={2}>
        <DateTimeField
          name={'ExpirationTime'}
          onChange={(e) =>
            setLot({
              ...lot,
              managementpolicyattrs: {
                ...lot.managementpolicyattrs,
                expirationtime: { value: e },
              },
            })
          }
          value={lot.managementpolicyattrs.expirationtime.value}
        />
      </Box>
      <Box mb={2}>
        <DateTimeField
          name={'DeletionTime'}
          onChange={(e) =>
            setLot({
              ...lot,
              managementpolicyattrs: {
                ...lot.managementpolicyattrs,
                deletiontime: { value: e },
              },
            })
          }
          value={lot.managementpolicyattrs.deletiontime.value}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default LotForm;
