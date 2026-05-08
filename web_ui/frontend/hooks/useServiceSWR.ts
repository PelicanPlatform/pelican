import useSWR, { SWRConfiguration, SWRResponse } from 'swr';
import { useContext } from 'react';
import { ErrorWithCause, errorToString } from '@/helpers/util';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { ApiService } from '@/helpers/api';

type FunctionKeys<T> = {
  [K in keyof T]: NonNullable<T[K]> extends Function ? K : never;
}[keyof T];

export default function useServiceSWR<
  TService extends ApiService<any, any, any, any, any>,
  TMethod extends FunctionKeys<TService>,
>(
  errorMessage: string,
  service: TService | null | undefined,
  methodName: TMethod,
  params: NonNullable<TService[TMethod]> extends (...args: infer P) => any
    ? Partial<P>
    : never,
  swrOptions?: SWRConfiguration
): SWRResponse<
  NonNullable<TService[TMethod]> extends (...args: any[]) => Promise<infer R>
    ? R
    : never,
  any
> {
  const dispatch = useContext(AlertDispatchContext);

  // 1. Stable Key Construction
  const shouldFetch = (() => {
    if (!service || !service[methodName]) {
      return false;
    }

    // Get the function's arity (number of required parameters)
    const fn = service![methodName] as Function;
    const arity = fn.length;

    // If the method requires no params, we can fetch with undefined params
    if (arity === 0) {
      return true;
    }

    // If params are not provided but method requires them, don't fetch
    if (params === undefined) {
      return false;
    }

    // Ensure we have enough params and none are undefined
    return (
      params.length >= arity &&
      params.slice(0, arity).every((p) => p !== undefined)
    );
  })();

  const key = shouldFetch ? [service!.id, methodName, ...(params ?? [])] : null;

  // 2. The Fetcher
  const fetcher = async () => {
    // We use service[methodName] directly and maintain 'this' context
    const fn = service![methodName] as Function;
    try {
      return await fn.apply(service, params ?? []);
    } catch (error) {
      if (error instanceof Error) {
        dispatch({
          type: 'openErrorAlert',
          payload: {
            title: errorMessage,
            error: errorToString(error as ErrorWithCause),
            onClose: () => dispatch({ type: 'closeAlert' }),
          },
        });
      }
      throw error;
    }
  };

  // 3. Return with casted response for full IDE support
  const x = useSWR(key, fetcher, swrOptions) as SWRResponse<
    NonNullable<TService[TMethod]> extends (...args: any[]) => Promise<infer R>
      ? R
      : never,
    any
  >;

  return x;
}
