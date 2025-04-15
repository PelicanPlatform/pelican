import useSWR, { BareFetcher, SWRConfiguration, SWRResponse } from 'swr';
import { useContext, useCallback } from 'react';

import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';

/**
 * A wrapper around useSWR that handles errors and dispatches alerts
 */
const useAlertSWR = (
  errorMessage: string,
  key: Parameters<typeof useSWR>[0],
  fetcher: () => Promise<Response>,
  config?: SWRConfiguration
): ReturnType<typeof useSWR<Response | undefined>> => {
  const dispatch = useContext(AlertDispatchContext);

  const wrappedFetcher = useCallback(() => {
    return alertOnError(fetcher, errorMessage, dispatch);
  }, [fetcher]);

  const { ...props } = useSWR(key, wrappedFetcher, config);

  return { ...props };
};

export default useAlertSWR;
