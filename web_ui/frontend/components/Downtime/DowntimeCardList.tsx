'use client';

import React, {
  ComponentType,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { Box, Grid, InputLabel, Select, MenuItem, FormControl } from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers';
import { DateTime } from 'luxon';

import { DowntimeCardProps } from './type';
import { CardList } from '@/components';
import { DowntimeGet } from '@/types';
import {
  CalendarDateTimeContext,
  CalendarDateTimeDispatchContext,
} from '@/components/Downtime/CalendarContext';

const sortTypes = {
  'startTime': {
    label: "Start Time",
    sortFn: (a: DowntimeGet, b: DowntimeGet) => a.startTime - b.startTime,
  },
  'updatedAt': {
    label: "Most Recently Updated",
    sortFn: (a: DowntimeGet, b: DowntimeGet) => b.updatedAt - a.updatedAt,
  }
}

interface DowntimeListProps {
  Card: ComponentType<any>;
  data?: DowntimeGet[];
}

function DowntimeCardList({ Card, data }: DowntimeListProps) {

  const [recentlyUpdated, setRecentlyUpdated] = useState(false);
  const range = useContext(CalendarDateTimeContext);
  const setRange = useContext(CalendarDateTimeDispatchContext);
  const [sortBy, setSortBy] = useState<keyof sortTypes>('updatedAt');

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

  const sortedDowntimes = useMemo(() => {
    return [...filteredData].sort(sortTypes[sortBy].sortFn);
  }, [filteredData, sortBy]);

  const downtimeCardProps = useMemo(() => {
    return sortedDowntimes?.map((downtime) => {
      return {
        downtime: downtime,
      };
    });
  }, [sortedDowntimes]);

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
        <Grid container spacing={1} mb={1} justifyContent={'space-between'}>
          <Grid gap={1} display={'flex'}>
            <DateTimePicker
              label={'Start Time'}
              value={DateTime.fromMillis(range.startTime)}
              onChange={(v) =>
                setRange({ ...range, startTime: v?.toMillis() || 0 })
              }
            />
            <DateTimePicker
              label={'End Time'}
              value={DateTime.fromMillis(range.endTime)}
              onChange={(v) =>
                setRange({ ...range, endTime: v?.toMillis() || 0 })
              }
            />
          </Grid>
          <Grid>
            <FormControl>
              <InputLabel id="sort-by-label">Sort By</InputLabel>
              <Select
                labelId="sort-by-label"
                value={sortBy}
                label="Sort By"
                onChange={(e) => setSortBy(e.target.value as keyof sortTypes)}
              >
                {Object.entries(sortTypes).map(([key, value]) => (
                  <MenuItem key={key} value={key}>
                    {value.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Box>
      <CardList<DowntimeCardProps>
        Card={Card}
        data={downtimeCardProps}
        keyGetter={(o) => o.downtime.id}
      />
    </>
  );
}

export default DowntimeCardList;
