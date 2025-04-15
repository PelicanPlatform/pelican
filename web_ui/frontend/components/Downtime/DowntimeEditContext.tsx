'use client';

/**
 * Creates the edit context for a downtime as well as contains the UI that allows the
 * user to edit the downtime.
 */

import {
  createContext,
  ReactNode,
  useState,
  SetStateAction,
  Dispatch,
} from 'react';
import { DowntimeGet, DowntimePost } from '@/types';
import { DowntimeModal } from '@/components/Downtime/ServerDowntime/DowntimeModal';

type DowntimeFormProps =
  | DowntimeGet
  | Omit<DowntimePost, 'severity' | 'class' | 'description'>;

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
        {downtime !== undefined && (
          <DowntimeModal
            open={true}
            onClose={() => setDowntime(undefined)}
            downtime={downtime}
          />
        )}
      </DowntimeEditDispatchContext.Provider>
    </DowntimeEditContext.Provider>
  );
};
