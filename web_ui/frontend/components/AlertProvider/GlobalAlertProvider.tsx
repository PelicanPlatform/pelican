'use client';

import { createContext, Dispatch, useReducer } from 'react';
import { AlertPortal, AlertPortalProps } from './AlertPortal';
import CodeBlock from '@/components/CodeBlock';
import { AlertReducerAction } from '@/components/AlertProvider/index';

const defaultGlobalAlertContext: AlertPortalProps | undefined = undefined;

export const GlobalAlertContext = createContext<AlertPortalProps | undefined>(
  defaultGlobalAlertContext
);

export const GlobalAlertDispatchContext = createContext<
  Dispatch<AlertReducerAction>
>(() => {});

export const GlobalAlertProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const [state, dispatch] = useReducer(alertReducer, defaultGlobalAlertContext);

  return (
    <GlobalAlertContext.Provider value={state}>
      <GlobalAlertDispatchContext.Provider value={dispatch}>
        {children}
        {state && <AlertPortal {...state} />}
      </GlobalAlertDispatchContext.Provider>
    </GlobalAlertContext.Provider>
  );
};

const alertReducer = (
  state: AlertPortalProps | undefined,
  action: AlertReducerAction
): AlertPortalProps | undefined => {
  switch (action.type) {
    case 'closeAlert':
      return undefined;
    case 'openErrorAlert':
      const { title, error, onClose } = action.payload;

      return {
        title,
        onClose,
        message: <CodeBlock>{error}</CodeBlock>,
        alertProps: {
          severity: 'error',
        },
      };
    case 'openAlert':
      return action.payload;
    default:
      return state;
  }
};

export default GlobalAlertProvider;
