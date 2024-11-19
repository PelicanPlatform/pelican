import { BooleanField } from './BooleanField';
import { StringField } from './StringField';
import { IntegerField } from './IntegerField';
import PubkeyField from './PubkeyField';

import EpochTimeField from '@/app/registry/components/CustomRegistrationField/EpochTimeField';
import EnumerationField from '@/app/registry/components/CustomRegistrationField/EnumerationField';
import { CustomRegistrationField as CustomRegistrationFieldConfiguration } from '@/components/configuration';
import type { CustomRegistrationField } from '@/components/configuration';

export type CustomRegistrationFieldProps =
  | (BaseCustomRegistrationFieldProps<number> & { type: 'int' })
  | (BaseCustomRegistrationFieldProps<string> & { type: 'string' })
  | (BaseCustomRegistrationFieldProps<boolean> & { type: 'bool' })
  | (BaseCustomRegistrationFieldProps<number> & { type: 'datetime' })
  | (BaseCustomRegistrationFieldProps<string> & { type: 'enum' });

export interface BaseCustomRegistrationFieldProps<T>
  extends CustomRegistrationFieldConfiguration {
  onChange: (value: T | null) => void;
  value?: T;
  displayed_name: string;
}

const CustomRegistrationField = ({
  ...props
}: CustomRegistrationFieldProps) => {
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
