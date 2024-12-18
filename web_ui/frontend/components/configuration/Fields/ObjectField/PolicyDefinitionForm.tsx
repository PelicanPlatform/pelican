import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

import {
  FormProps,
  PolicyDefinition,
  Lot,
  StringSliceField,
} from '@/components/configuration';
import {
  StringField,
  BooleanField,
  ObjectField,
  LotForm,
} from '@/components/configuration';

const verifyForm = (x: PolicyDefinition) => {
  return x.policyname != '' && x.purgeorder.length == 4;
};

const createDefaultPolicyDefinition = (): PolicyDefinition => {
  return {
    policyname: '',
    purgeorder: ['del', 'exp', 'opp', 'ded'],
    discoverprefixes: false,
    mergelocalwithdiscovered: false,
    divideunallocated: false,
    lots: [],
  };
};

const PolicyDefinitionForm = ({
  onSubmit,
  value,
}: FormProps<PolicyDefinition>) => {
  const [policyDefinition, setPolicyDefinition] =
    React.useState<PolicyDefinition>(value || createDefaultPolicyDefinition());

  const submitHandler = useCallback(() => {
    if (!verifyForm(policyDefinition)) {
      return;
    }
    onSubmit(policyDefinition);
  }, [policyDefinition]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'PolicyName'}
          onChange={(e) =>
            setPolicyDefinition({ ...policyDefinition, policyname: e })
          }
          value={policyDefinition.policyname}
        />
      </Box>
      <Box mb={2}>
        <StringSliceField
          name={'PurgeOrder'}
          onChange={(e) =>
            setPolicyDefinition({
              ...policyDefinition,
              purgeorder: e as PolicyDefinition['purgeorder'],
            })
          }
          value={policyDefinition.purgeorder}
          verify={verifyPurgeOrder}
        />
      </Box>
      <Box mb={2}>
        <BooleanField
          name={'DiscoverPrefixes'}
          onChange={(e) =>
            setPolicyDefinition({ ...policyDefinition, discoverprefixes: e })
          }
          value={policyDefinition.discoverprefixes}
        />
      </Box>
      <Box mb={2}>
        <BooleanField
          name={'MergeLocalWithDiscovered'}
          onChange={(e) =>
            setPolicyDefinition({
              ...policyDefinition,
              mergelocalwithdiscovered: e,
            })
          }
          value={policyDefinition.mergelocalwithdiscovered}
        />
      </Box>
      <Box mb={2}>
        <BooleanField
          name={'DivideUnallocated'}
          onChange={(e) =>
            setPolicyDefinition({ ...policyDefinition, divideunallocated: e })
          }
          value={policyDefinition.divideunallocated}
        />
      </Box>
      <Box mb={2}>
        <ObjectField
          name={'Lots'}
          onChange={(e) =>
            setPolicyDefinition({ ...policyDefinition, lots: e })
          }
          value={policyDefinition.lots}
          Form={LotForm}
          keyGetter={(x: Lot) => x.lotname}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

const verifyPurgeOrder = (x: string[]) => {
  // Check the required values are present
  if (
    !(
      x.includes('del') &&
      x.includes('exp') &&
      x.includes('opp') &&
      x.includes('ded')
    )
  ) {
    return "Purge order must contain 'del', 'exp', 'opp', and 'ded'";
  }

  // Check that only valid values are present
  if (x.length != 4) {
    return 'Purge order must contain exactly [del, exp, opp, ded] in user defined order';
  }
};

export default PolicyDefinitionForm;
