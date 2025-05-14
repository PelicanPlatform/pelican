'use client';

import Calendar from 'react-calendar';
import 'react-calendar/dist/Calendar.css';
import './calendar.css';

import DateTile from './DateTile';
import { useContext } from 'react';
import { DowntimeGet } from '@/types';
import { CalendarDateTimeDispatchContext } from '@/components/Downtime/CalendarContext';

const DowntimeCalendar = ({ data }: { data?: DowntimeGet[] }) => {
  const setRange = useContext(CalendarDateTimeDispatchContext);

  return (
    <Calendar
      selectRange
      returnValue={'range'}
      onActiveStartDateChange={(v) => {
        const startOfMonth = v.activeStartDate;

        // Check if the startOfMonth is set
        if (!startOfMonth) {
          return;
        }

        const endOfMonth = new Date(
          startOfMonth.getFullYear(),
          startOfMonth.getMonth() + 1,
          0
        );

        setRange({
          startTime: startOfMonth.getTime(),
          endTime: endOfMonth.getTime(),
        });
      }}
      onChange={(v, e) => {
        if (Array.isArray(v) && v[0] && v[1]) {
          setRange({
            startTime: v[0].getTime(),
            endTime: v[1].getTime(),
          });
        }
      }}
      tileContent={(args) => <DateTile downtimes={data} {...args} />}
    />
  );
};

export default DowntimeCalendar;
