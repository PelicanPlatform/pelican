import useSWR, { SWRConfiguration, SWRResponse } from 'swr';
import { useContext } from 'react';
import { ErrorWithCause,  errorToString } from '@/helpers/util';
import {AlertDispatchContext} from "@/components/AlertProvider";

export default function useServiceSWR<
  F extends (...args: any[]) => Promise<any>
>(
  errorMessage: string,
  serviceFn: F | null,
  params?: Parameters<F>,
  swrOptions?: SWRConfiguration
): SWRResponse<Awaited<ReturnType<F>>, any> {
  const dispatch = useContext(AlertDispatchContext);

  const key = serviceFn ? [serviceFn, ...(params ?? [])] : null;

  const fetcher = async (keyArr: readonly unknown[]) => {
    const fn = keyArr[0] as F;
    const args = keyArr.slice(1) as Parameters<F>;

    try {
      return await fn(...args);
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

      // Re-throw the error so that SWR can handle it (e.g. for retries)
      throw error;
    }
  };

  return useSWR(key, fetcher, swrOptions) as SWRResponse<
    Awaited<ReturnType<F>>,
    any
  >;
}
