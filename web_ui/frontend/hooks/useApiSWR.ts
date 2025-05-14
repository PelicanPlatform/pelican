import useSWR, { SWRConfiguration } from 'swr';
import { useCallback, useContext } from 'react';

import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { fetchApi } from '@/helpers/api';

type useSWRProps = Parameters<typeof useSWR>;

/**
 * A wrapper around useSWR that handles API calls and dispatches alerts
 */
function useApiSWR<T>(
  errorMessage: string,
  key: useSWRProps[0],
  fetcher: () => Promise<Response>,
  config?: SWRConfiguration
): ReturnType<typeof useSWR<T | undefined>> {
  const dispatch = useContext(AlertDispatchContext);

  const wrappedFetcher = useCallback(() => {
    return alertOnError<T>(
      async () => {
        const response = await fetchApi(fetcher);
        return (await response.json()) as T;
      },
      errorMessage,
      dispatch
    );
  }, [fetcher]);

  const { ...props } = useSWR(key, wrappedFetcher, config);
  return props;
}

export default useApiSWR;
