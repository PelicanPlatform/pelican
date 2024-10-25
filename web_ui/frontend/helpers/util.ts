import { ServerType } from '@/index';
import { Dispatch } from 'react';
import { AlertReducerAction } from '@/components/AlertProvider';

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

/**
 * Extract the value from a object via a list of keys
 * @param obj
 * @param keys
 */
export function getObjectValue<T>(obj: any, keys: string[]): T | undefined {
  const currentValue = obj?.[keys[0]];
  if (keys.length == 1) {
    return currentValue;
  }
  return getObjectValue(currentValue, keys.slice(1));
}

/**
 * Get the error message from a response
 * @param response
 */
export const getErrorMessage = async (response: Response): Promise<string> => {
  try {
    let data = await response.json();
    return response.status + ': ' + data['msg'];
  } catch (e) {
    return response.status + ': ' + response.statusText;
  }
};

export type TypeFunction<T, F = any> = (x?: F) => T;

export type TypeOrTypeFunction<T, F = any> = T | TypeFunction<T, F>;

/**
 * Evaluate a function or return a value
 * @param o Function or value
 * @param functionProps Function properties
 */
export function evaluateOrReturn<T, F>(
  o: TypeOrTypeFunction<T, F>,
  functionProps?: F
): T {
  if (typeof o === 'function') {
    return (o as TypeFunction<T, F>)(functionProps);
  }

  return o as T;
}


/**
 * Get the average of an array of numbers
 * @param arr Array of numbers
 */
export const average = (arr: number[]) => {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
};

type ErrorWithCause = Error & { cause?: Error };


/**
 * If an error is caught from f then display the error via an alert UI
 */
export async function alertOnError<T=any>(
  f: () => Promise<T> | T | undefined,
  title: string = 'Error',
  dispatch: Dispatch<AlertReducerAction>
){
  try {
    return await f();
  } catch (error) {
    console.error(error);
    if(error instanceof Error) {
      dispatch({
        type: "openErrorAlert",
        payload: {
          title,
          error: errorToString(error as ErrorWithCause),
          onClose: () => dispatch({ type: "closeAlert" })
        }
      })
    }
  }
}

/**
 * Convert a error into a string
 * @param error
 */
export const errorToString = (error: ErrorWithCause) : string => {

  if(error?.cause){

    // Check that error is instance of Error
    if(!(error?.cause instanceof Error)) {
      console.error("Malformed error, cause is not an instance of Error", error)
    }

    return `${error.message}\n↳ ${errorToString(error.cause as ErrorWithCause)}`
  }

  return `${error.message}`
}
