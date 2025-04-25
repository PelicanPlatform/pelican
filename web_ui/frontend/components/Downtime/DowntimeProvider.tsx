import { DowntimeEditProvider } from '@/components/Downtime/DowntimeEditContext';
import { CalendarDateTimeProvider } from '@/components/Downtime/CalendarContext';
import { ReactNode } from 'react';

const DowntimeProvider = ({ children }: { children: ReactNode }) => {
  return (
    <DowntimeEditProvider>
      <CalendarDateTimeProvider>{children}</CalendarDateTimeProvider>
    </DowntimeEditProvider>
  );
};

export default DowntimeProvider;
