'use client';

import { createContext, Dispatch, useReducer } from 'react';
import { AlertPortal, AlertPortalProps } from './AlertPortal';
import CodeBlock from '@/components/CodeBlock';
import {AlertReducerAction} from "@/components/AlertProvider/index";

const defaultAlertContext: AlertPortalProps | undefined = undefined;

export const AlertContext = createContext<AlertPortalProps | undefined>(
  defaultAlertContext
);

export const AlertDispatchContext = createContext<Dispatch<AlertReducerAction>>(
  () => {}
);

export const AlertProvider = ({ children }: { children: React.ReactNode }) => {
  const [state, dispatch] = useReducer(alertReducer, defaultAlertContext);

  return (
    <AlertContext.Provider value={state}>
      <AlertDispatchContext.Provider value={dispatch}>
        {children}
        {state && <AlertPortal {...state} />}
      </AlertDispatchContext.Provider>
    </AlertContext.Provider>
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
