'use client';

import Calendar from 'react-calendar';
import 'react-calendar/dist/Calendar.css';
import './calendar.css';

import DateTile from './DateTile';
import {useContext, useMemo, useState} from 'react';
import { DowntimeGet, DowntimeSeverity } from '@/types';
import { CalendarDateTimeDispatchContext } from '@/components/Downtime/CalendarContext';
import getDaysInMonth from "@/helpers/getDaysInMonth";

const DowntimeCalendar = ({ data = [] }: { data?: DowntimeGet[] }) => {
  const setRange = useContext(CalendarDateTimeDispatchContext);

  const [activeStartDate, setActiveStartDate] = useState<Date>(new Date());

  // Downtimes for this month binned by date for use in the DateTile component
  const binnedDowntimes: Record<string, Record<DowntimeSeverity, number>> = useMemo(() => {

    // Iterate the dates in the current month and bin the downtimes by date
    return getDaysInMonth(activeStartDate).reduce((a, d) => {

      // Determine downtimes that intersect with the current date
      const dateRelevantDowntimes = data?.filter((downtime) => {
        const start = new Date(downtime.startTime);
        const end = new Date(downtime.endTime);

        const dateStart = new Date(d.getFullYear(), d.getMonth(), d.getDate());
        const dateEnd = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1);

        return (
          (start >= dateStart && start < dateEnd) || // Starts on this date
          (end > dateStart && end <= dateEnd) ||     // Ends on this date
          (start < dateStart && end > dateEnd)       // Is contained within this date
        );

      });

      a[d.toISOString()] = binBySeverity(dateRelevantDowntimes || []);

      return a

    }, {} as Record<string, Record<DowntimeSeverity, number>>);
  }, [activeStartDate, data]);

  // Unpack the month of downtimes and determine the maximum value in a single day + category to scale visualizations
  const maxValue = useMemo(() => {
    return Math.max(...Object.values(binnedDowntimes).map(o => Math.max(...Object.values(o))), 0);
  }, [binnedDowntimes]);

  return (
    <Calendar
      selectRange
      returnValue={'range'}
      calendarType={'gregory'}
      onActiveStartDateChange={(v) => {

        // Update the active start date if it is not null
        v.activeStartDate !== null && setActiveStartDate(v.activeStartDate);

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
        return (
          <DateTile
            binnedDowntimes={binnedDowntimes[args.date.toISOString()]}
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
