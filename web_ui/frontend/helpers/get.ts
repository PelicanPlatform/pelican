import { Config, ParameterValueRecord } from '@/components/configuration';
import { getConfig as getConfigResponse } from '@/helpers/api'
import { flattenObject } from '@/app/config/util';

export const getConfig = async (): Promise<ParameterValueRecord> => {
  let response = await getConfigResponse();
  let data = await response.json();
  let flatData = flattenObject(data);
  return flatData;
};
