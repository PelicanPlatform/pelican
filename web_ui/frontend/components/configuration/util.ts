import { getErrorMessage } from '@/helpers/util';
import {
  ParameterMetadata,
  ParameterMetadataRecord,
} from '@/components/configuration';

export const stringSort = (a: string, b: string) => {
  return a.localeCompare(b);
};

export const createId = (name: string) => {
  return name.replace(/[^a-zA-Z0-9]/g, '_');
};

const buildPatchHelper = (keys: string[], value: any): any => {
  if (keys.length === 1) {
    return { [keys[0]]: value };
  }
  return { [keys[0]]: buildPatchHelper(keys.slice(1), value) };
};

export const buildPatch = (name: string, value: any) => {
  return buildPatchHelper(name.split('.'), value);
};

export const submitConfigChange = async (data: any) => {
  const response = await fetch('/api/v1.0/config', {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });

  if (response.ok) {
    return response.json();
  } else {
    throw new Error(await getErrorMessage(response));
  }
};

export const verifyIpAddress = (ip: string) => {
  const isValidv4 =
    /^(?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(?!$)|$)){4}$/.test(ip);
  const isValidv6 =
    /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/.test(
      ip
    );
  return isValidv4 || isValidv6 ? undefined : 'Invalid IP Address';
};

export const verifyLatitude = (latitude: string) => {
  const isValid =
    /^(\+|-)?(?:90(?:(?:\.0{1,6})?)|(?:[0-9]|[1-8][0-9])(?:(?:\.[0-9]{1,6})?))$/.test(
      latitude
    );
  return isValid ? undefined : 'Invalid Latitude';
};

export const verifyLongitude = (longitude: string) => {
  const isValid =
    /^(\+|-)?(?:180(?:(?:\.0{1,6})?)|(?:[0-9]|[1-9][0-9]|1[0-7][0-9])(?:(?:\.[0-9]{1,6})?))$/.test(
      longitude
    );
  return isValid ? undefined : 'Invalid Longitude';
};

/**
 * The input is a record with . delimited keys and the output is a nested object
 *
 * @param parameters
 */
export const expandParameterKeys = (
  parameters: Record<string, ParameterMetadata>[]
): ParameterMetadataRecord => {
  const output: ParameterMetadataRecord = {};
  parameters.forEach((record) => {
    const [key, value] = Object.entries(record)[0];
    const keys = key.split('.');
    const lastKey = keys.pop() as string;
    let current: Record<string, any> = output;
    keys.forEach((k) => {
      if (!current[k]) {
        current[k] = {};
      }
      current = current[k];
    });
    current[lastKey] = value;
  });
  return output;
};
