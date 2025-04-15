'use client';

import React, { useContext, useEffect, useMemo, useState } from 'react';
import ServerDowntimeCard, {
  ServerDowntimeCardProps,
} from './ServerDowntimeCard';
import { CardList } from '@/components';
import { DowntimeGet } from '@/types';
import useApiSWR from '@/hooks/useApiSWR';
import { ServerDowntimeKey } from '@/components/Downtime';
import {
  CalendarDateTimeContext,
  CalendarDateTimeDispatchContext,
} from '@/components/Downtime/CalendarContext';
import { Box, Grid } from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers';
import { DateTime } from 'luxon';
import { getDowntime } from '@/helpers/api';

interface DowntimeListProps {
  data?: DowntimeGet[];
}

function DowntimeList({}: DowntimeListProps) {
  const [recentlyUpdated, setRecentlyUpdated] = useState(false);
  const range = useContext(CalendarDateTimeContext);
  const setRange = useContext(CalendarDateTimeDispatchContext);
  const { data } = useApiSWR<DowntimeGet[]>(
    'Failed to fetch downtimes',
    ServerDowntimeKey,
    getDowntime
  );

  // Filter the data based on the range
  const filteredData = useMemo(() => {
    if (!data) return [];
    if (!range) return data;

    return data.filter((downtime) => {
      // Check if downtime starts before but ends inside range
      const endsInside =
        downtime.endTime >= range.startTime &&
        downtime.endTime <= range.endTime;

      // Check if the downtime starts inside the range but ends after
      const startsInside =
        downtime.startTime >= range.startTime &&
        downtime.startTime <= range.endTime;

      // Check if the downtime spans the range
      const spansRange =
        downtime.startTime <= range.startTime &&
        (downtime.endTime >= range.endTime || downtime.endTime === -1);

      return endsInside || startsInside || spansRange;
    });
  }, [data, range]);

  const downtimeCardProps = useMemo(() => {
    return filteredData?.map((downtime) => {
      return {
        downtime: downtime,
      };
    });
  }, [filteredData]);

  useEffect(() => {
    setRecentlyUpdated(true);
    const timeout = setTimeout(() => setRecentlyUpdated(false), 1000); // Pulse duration
    return () => clearTimeout(timeout);
  }, [range.endTime, range.startTime]); // Trigger effect when `range` changes

  return (
    <>
      <Box
        sx={{
          animation: recentlyUpdated ? 'pulse .5s ease-in-out' : 'none',
          '@keyframes pulse': {
            '0%': { opacity: 1 },
            '50%': { opacity: 0 },
            '100%': { opacity: 1 },
          },
        }}
      >
        <Grid container spacing={1} mb={1}>
          <Grid item>
            <DateTimePicker
              label={'Start Time'}
              value={DateTime.fromMillis(range.startTime)}
              onChange={(v) =>
                setRange({ ...range, startTime: v?.toMillis() || 0 })
              }
            />
          </Grid>
          <Grid item>
            <DateTimePicker
              label={'End Time'}
              value={DateTime.fromMillis(range.endTime)}
              onChange={(v) =>
                setRange({ ...range, endTime: v?.toMillis() || 0 })
              }
            />
          </Grid>
        </Grid>
      </Box>
      <CardList<ServerDowntimeCardProps>
        Card={ServerDowntimeCard}
        data={downtimeCardProps}
      />
    </>
  );
}

export default DowntimeList;
