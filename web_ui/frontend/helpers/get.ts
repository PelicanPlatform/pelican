import { Config, ParameterValueRecord } from '@/components/configuration';
import { flattenObject } from '@/app/config/util';

export const getConfig = async (): Promise<ParameterValueRecord> => {
  let response = await fetch('/api/v1.0/config');
  let data = await response.json();
  let flatData = flattenObject(data);
  return flatData;
};
