import { ServerType } from '@/index';

const stringToTime = (time: string) => {
  return new Date(Date.parse(time)).toLocaleString();
};

export const getEnabledServers = async (): Promise<ServerType[]> => {
  const response = await fetch('/api/v1.0/servers');
  if (response.ok) {
    const data = await response.json();
    const servers = data?.servers;

    if (servers == undefined) {
      console.error('No servers found', response);
      return [];
    }

    return servers;
  }

  return [];
};

export const getOauthEnabledServers = async () => {
  const response = await fetch('/api/v1.0/auth/oauth');
  if (response.ok) {
    const data = await response.json();
    const servers = data?.oidc_enabled_servers;

    if (servers == undefined) {
      console.error('No servers found', response);
      return [];
    }

    return servers;
  }
};

export function getObjectValue<T>(obj: any, keys: string[]): T | undefined {
  const currentValue = obj?.[keys[0]];
  if (keys.length == 1) {
    return currentValue;
  }
  return getObjectValue(currentValue, keys.slice(1));
}

export const getErrorMessage = async (response: Response): Promise<string> => {
  let message;
  try {
    let data = await response.json();
    message = response.status + ': ' + data['msg'];
  } catch (e) {
    message = response.status + ': ' + response.statusText;
  }
  return message;
};

export type TypeFunction<T, F = any> = (() => T) | ((x: F) => T);

export type TypeOrTypeFunction<T, F = any> = T | TypeFunction<T, F>;

export function evaluateOrReturn<T, F>(o: TypeOrTypeFunction<T>, functionProps: F): T {

  if(typeof o === 'function') {
    return (o as TypeFunction<T, F>)(functionProps);
  }

  return o as T;
}

export const average = (arr: number[]) => {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}
