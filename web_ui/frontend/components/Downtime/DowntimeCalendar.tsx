'use client';

import Calendar from 'react-calendar';
import 'react-calendar/dist/Calendar.css';
import './calendar.css';

import DateTile from './DateTile';
import { useContext, useState } from 'react';
import { DowntimeGet, DowntimeSeverity } from '@/types';
import { CalendarDateTimeDispatchContext } from '@/components/Downtime/CalendarContext';

const DowntimeCalendar = ({ data }: { data?: DowntimeGet[] }) => {
  const setRange = useContext(CalendarDateTimeDispatchContext);

  const [maxValue, setMaxValue] = useState<number>(1);

  return (
    <Calendar
      selectRange
      returnValue={'range'}
      calendarType={'gregory'}
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
      tileContent={(args) => {
        const tileDowntimes = data?.filter((downtime) => {
          const start = new Date(downtime.startTime);
          const end = new Date(downtime.endTime);
          return (
            args.date >= start && (args.date <= end || downtime.endTime === -1)
          );
        });

        const binnedDowntimes = binBySeverity(tileDowntimes || []);

        // Update maxValue
        setMaxValue((p) => Math.max(p, ...Object.values(binnedDowntimes)));

        return (
          <DateTile
            binnedDowntimes={binnedDowntimes}
            maxValue={maxValue}
            {...args}
          />
        );
      }}
    />
  );
};

const binBySeverity = (downtimes: DowntimeGet[]) => {
  let binnedSeverities = {
    "No Significant Outage Expected (you shouldn't notice)": 0,
    'Intermittent Outage (may be up for some of the time)': 0,
    'Severe (most services down)': 0,
    'Outage (completely inaccessible)': 0,
  } as Record<DowntimeSeverity, number>;

  // Loop through the downtimes and bin them by severity
  downtimes.forEach((d) => (binnedSeverities[d.severity] += 1));

  return binnedSeverities;
};

export default DowntimeCalendar;
