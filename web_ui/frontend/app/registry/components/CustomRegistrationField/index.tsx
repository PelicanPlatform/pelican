import type { CustomRegistrationField } from '@/components/Config/index';
import { BooleanField } from './BooleanField';
import { ErrorField } from './ErrorField';
import { StringField } from './StringField';
import { IntegerField } from './IntegerField';
import PubkeyField from './PubkeyField';

import { CustomRegistrationFieldPropsEnum } from './index.d';
import EpochTimeField from '@/app/registry/components/CustomRegistrationField/EpochTimeField';
import EnumerationField from '@/app/registry/components/CustomRegistrationField/EnumerationField';

const CustomRegistrationField = ({
  ...props
}: CustomRegistrationFieldPropsEnum) => {
  // If the field is the pubkey field, render the pubkey field
  if (props.type == 'string' && props.name === 'pubkey') {
    return <PubkeyField {...props} />;
  }

  switch (props.type) {
    case 'bool':
      return <BooleanField {...props} />;

    case 'string':
      return <StringField {...props} />;

    case 'int':
      return <IntegerField {...props} />;

    case 'datetime':
      return <EpochTimeField {...props} />;

    case 'enum':
      return <EnumerationField {...props} />;
  }
};

export default CustomRegistrationField;
export { CustomRegistrationField };
