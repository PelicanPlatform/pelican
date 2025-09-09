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
  useEffect,
  useState,
} from 'react';

interface DateTimeRange {
  startTime: number;
  endTime: number;
}

const tempRange = {
  startTime: 0,
  endTime: 0,
};

export const CalendarDateTimeContext = createContext<DateTimeRange>(tempRange);
export const CalendarDateTimeDispatchContext = createContext<
  Dispatch<SetStateAction<DateTimeRange>>
>(() => {});

export const CalendarDateTimeProvider = ({
  children,
}: {
  children: ReactNode;
}) => {
  const [range, setRange] = useState<DateTimeRange>(tempRange);

  // Set default to current month on load
  useEffect(() => {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    setRange({
      startTime: startOfMonth.getTime(),
      endTime: endOfMonth.getTime(),
    });
  }, []);

  return (
    <CalendarDateTimeContext.Provider value={range}>
      <CalendarDateTimeDispatchContext.Provider value={setRange}>
        {children}
      </CalendarDateTimeDispatchContext.Provider>
    </CalendarDateTimeContext.Provider>
  );
};
