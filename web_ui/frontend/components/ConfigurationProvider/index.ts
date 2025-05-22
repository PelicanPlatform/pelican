import { ParameterValueRecord } from '@/components/configuration';

export type ConfigurationContextState = {
  configuration: ParameterValueRecord | undefined;
  patch: ParameterValueRecord;
  merged: ParameterValueRecord;
  setPatch: (patch: any) => void;
  mutate: () => void;
  submit: () => Promise<boolean>;
  submitting: boolean;
};
