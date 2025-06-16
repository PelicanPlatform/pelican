'use client';

/**
 * Creates the edit context for a downtime as well as contains the UI that allows the
 * user to edit the downtime.
 */

import {
  createContext,
  Dispatch,
  ReactNode,
  SetStateAction,
  useState,
} from 'react';
import { DowntimeGet, DowntimePost } from '@/types';

type DowntimeFormProps =
  | DowntimeGet
  | Partial<DowntimePost>;

export const DowntimeEditContext = createContext<DowntimeFormProps | undefined>(
  undefined
);
export const DowntimeEditDispatchContext = createContext<
  Dispatch<SetStateAction<DowntimeFormProps | undefined>>
>(() => {});

export const DowntimeEditProvider = ({ children }: { children: ReactNode }) => {
  const [downtime, setDowntime] = useState<DowntimeFormProps | undefined>(
    undefined
  );

  return (
    <DowntimeEditContext.Provider value={downtime}>
      <DowntimeEditDispatchContext.Provider value={setDowntime}>
        {children}
      </DowntimeEditDispatchContext.Provider>
    </DowntimeEditContext.Provider>
  );
};
