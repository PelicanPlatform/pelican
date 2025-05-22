'use client';

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from 'react';
import { ConfigurationContextState } from '.';
import useSWR from 'swr';
import {
  ParameterValueRecord,
  submitConfigChange,
} from '@/components/configuration';
import { getConfig } from '@/helpers/get';
import { merge } from 'lodash';
import { alertOnError } from '@/helpers/util';
import { GlobalAlertDispatchContext } from '@/components/AlertProvider';

export const ConfigurationContext = createContext<ConfigurationContextState>({
  configuration: undefined,
  merged: {},
  patch: {},
  setPatch: () => {
    console.error('setPatch not set');
  },
  mutate: () => {
    console.error('mutate not set');
  },
  submit: async () => {
    console.error('submit not set');
    return false;
  },
  submitting: false,
} as ConfigurationContextState);

export const ConfigurationProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const dispatch = useContext(GlobalAlertDispatchContext);
  const [patch, _setPatch] = useState<ParameterValueRecord>({});
  const [submitting, setSubmitting] = useState<boolean>(false);
  const { data: configuration, mutate } = useSWR<ParameterValueRecord>(
    'getConfig',
    getConfig
  );
  const setPatch = useCallback(
    (fieldPatch: any) => {
      _setPatch((p: any) => {
        return { ...p, ...fieldPatch };
      });
    },
    [_setPatch]
  );
  const merged = useMemo(() => {
    return merge(structuredClone(configuration), structuredClone(patch));
  }, [configuration, patch]);
  const submit = useCallback(async () => {
    setSubmitting(true);
    const response = await alertOnError(
      async () => await submitConfigChange(patch),
      'Error submitting configuration change',
      dispatch
    );
    setSubmitting(false);

    // If there is a response from the server, it means the request was successful
    if (response) {
      setPatch({});
      await mutate();
      return true;
    }

    return false;
  }, [patch, mutate, dispatch, setPatch]);

  return (
    <ConfigurationContext.Provider
      value={{
        configuration,
        patch,
        merged,
        setPatch,
        mutate,
        submit,
        submitting,
      }}
    >
      {children}
    </ConfigurationContext.Provider>
  );
};

export default ConfigurationProvider;
