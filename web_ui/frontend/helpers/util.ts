import { ServerType } from '@/index';
import { Dispatch } from 'react';
import { AlertReducerAction } from '@/components/AlertProvider';

const stringToTime = (time: string) => {
  return new Date(Date.parse(time)).toLocaleString();
};

export interface ServerInfo {
  servers: ServerType[];
  /**
   * True when this server runs an Origin with Origin.EnableStandaloneMode --
   * it belongs to no federation, so there is no registry to register at, no
   * director to advertise to, and nothing consuming its downtime records.
   * Pages use this to hide federation-only affordances rather than render
   * them as permanently broken.
   */
  standaloneOrigin: boolean;
}

export const getServerInfo = async (): Promise<ServerInfo> => {
  const response = await fetch('/api/v1.0/servers');
  if (response.ok) {
    const data = await response.json();
    const servers = data?.servers;

    if (servers == undefined) {
      console.error('No servers found', response);
      return { servers: [], standaloneOrigin: false };
    }

    return { servers, standaloneOrigin: !!data?.standaloneOrigin };
  }

  return { servers: [], standaloneOrigin: false };
};

export const getEnabledServers = async (): Promise<ServerType[]> => {
  return (await getServerInfo()).servers;
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

export type ErrorWithCause = Error & { cause?: Error };

/**
 * If an error is caught from f then display the error via an alert UI
 */
export async function alertOnError<T = any>(
  f: () => Promise<T> | T,
  title: string = 'Error',
  dispatch: Dispatch<AlertReducerAction>,
  passError: boolean = false
) {
  try {
    return await f();
  } catch (error) {
    console.error(error);
    if (error instanceof Error) {
      dispatch({
        type: 'openErrorAlert',
        payload: {
          title,
          error: errorToString(error as ErrorWithCause),
          onClose: () => dispatch({ type: 'closeAlert' }),
        },
      });

      // Re throw the error if requested
      if (passError) {
        throw error;
      }
    }
  }
}

/**
 * Convert a error into a string
 * @param error
 */
export const errorToString = (error: ErrorWithCause): string => {
  if (error?.cause) {
    // Check that error is instance of Error
    if (!(error?.cause instanceof Error)) {
      console.error(
        'Malformed error, cause is not an instance of Error',
        error
      );
    }

    return `${error.message}\n↳ ${errorToString(error.cause as ErrorWithCause)}`;
  }

  return `${error.message}`;
};

/**
 * Multi-sort objects, prioritizing the first sort function
 */
export const multiSort = <T>(arr: T[], ...args: ((a: T, b: T) => number)[]) => {
  return arr.sort((a, b) => {
    for (const fn of args) {
      const result = fn(a, b);
      if (result !== 0) {
        return result;
      }
    }
    return 0;
  });
};

/**
 * Convert an object to a string key that is robust to unsorted lists
 */
export const objectToDeterministicString = (o: any): string => {
  return Object.keys(o)
    .sort()
    .reduce((p, k) => {
      const value = o[k];

      // If the value is an array then ignore it
      if (Array.isArray(value)) {
        return p;
      }

      // If the object is an object then convert it to a string
      if (typeof value === 'object' && value !== null) {
        return p + k + ':' + objectToDeterministicString(value);
      }

      return p + k + ':' + value;
    }, '');
};
