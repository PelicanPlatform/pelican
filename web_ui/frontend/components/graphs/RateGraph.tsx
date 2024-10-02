/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import dynamic from 'next/dynamic';

import React, { useEffect, useState } from 'react';
import { ChartOptions, ChartDataset, ChartData } from 'chart.js';

import { DateTime } from 'luxon';

import 'chartjs-adapter-luxon';

import {
  BoxProps,
  Grid
} from '@mui/material';

import {
  query_rate,
  TimeDuration,
  DurationType,
  PrometheusQuery,
  prometheusResultToDataPoints,
} from '@/components/graphs/prometheus';

import { GraphDrawer, ResolutionInput, RateInput } from './Drawer';

const Graph = dynamic(() => import('@/components/graphs/Graph'), {
  ssr: false,
});

interface RateGraphDrawerProps {
  reset: Function;
  rate: TimeDuration;
  resolution: TimeDuration;
  duration: TimeDuration;
  time: DateTime;
  setRate: Function;
  setResolution: Function;
  setDuration: Function;
  setTime: Function;
}

function RateGraphDrawer({
  reset,
  rate,
  resolution,
  duration,
  time,
  setRate,
  setResolution,
  setDuration,
  setTime,
}: RateGraphDrawerProps) {
  return (
    <GraphDrawer
      duration={duration}
      time={time}
      setDuration={setDuration}
      setTime={setTime}
      reset={reset}
    >
      <Grid container spacing={2}>
        <Grid item xs={12}>
          <RateInput rate={rate} setRate={setRate} />
        </Grid>
        <Grid item xs={12}>
          <ResolutionInput
            resolution={resolution}
            setResolution={setResolution}
          />
        </Grid>
      </Grid>
    </GraphDrawer>
  );
}

interface RateGraphProps {
  boxProps?: BoxProps;
  metrics: string[];
  rate?: TimeDuration;
  duration?: TimeDuration;
  resolution?: TimeDuration;
  options?: ChartOptions<'line'>;
  datasetOptions?:
    | Partial<ChartDataset<'line'>>
    | Partial<ChartDataset<'line'>>[];
}

export default function RateGraph({
  boxProps,
  metrics,
  rate = new TimeDuration(30, 'm'),
  duration = new TimeDuration(1, 'd'),
  resolution = new TimeDuration(1, 'm'),
  options = {},
  datasetOptions = {},
}: RateGraphProps) {
  let default_rate = rate;
  let default_duration = duration;
  let default_resolution = resolution;

  let reset = () => {
    setRate(default_rate.copy());
    setDuration(default_duration.copy());
    setResolution(default_resolution.copy());
    setTime(DateTime.now());
  };

  let [_rate, setRate] = useState(rate);
  let [_duration, _setDuration] = useState(duration);
  let [_resolution, setResolution] = useState(resolution);
  let [_time, _setTime] = useState<DateTime>(DateTime.now());

  // Create some reasonable defaults for the graph
  let setDuration = (duration: TimeDuration) => {
    if (duration.value == 1) {
      setRate(new TimeDuration(30, 'm'));
      setResolution(new TimeDuration(10, 'm'));
    } else if (duration.value == 7) {
      setRate(new TimeDuration(3, 'h'));
      setResolution(new TimeDuration(30, 'm'));
    } else if (duration.value == 31) {
      setRate(new TimeDuration(12, 'h'));
      setResolution(new TimeDuration(12, 'h'));
    }

    _setDuration(duration);
  };

  let setTime = (time: DateTime) => {
    // If it's not today, then set time to the end of that day
    // If it's today, then set to date.now
    //
    // This helps us to get the latest data while not going over the wanted time range
    // If we set the time to the future, PromQL will give you random data in the future to
    // interpolate the missing ones
    if (time.hasSame(DateTime.now(), 'day')) {
      time = DateTime.now();
    } else {
      time.set({ hour: 23, minute: 59, second: 59, millisecond: 999 });
    }
    _setTime(time);
  };

  async function getData() {
    let chartData: ChartData<'line', any, any> = {
      datasets: await Promise.all(
        metrics.map(async (metric, index) => {
          let datasetOption: Partial<ChartDataset<'line'>> = {};
          if (datasetOptions instanceof Array) {
            try {
              datasetOption = datasetOptions[index];
            } catch (e) {
              console.error(
                'datasetOptions is an array, but the number of elements < the number of metrics'
              );
            }
          } else {
            datasetOption = datasetOptions;
          }

          let updatedTime = _time;
          if (updatedTime.hasSame(DateTime.now(), 'day')) {
            updatedTime = DateTime.now();
          }

          const queryResponse = await query_rate({
            metric,
            rate: _rate,
            duration: _duration,
            resolution: _resolution,
            time: updatedTime,
          })

          const dataPoints = prometheusResultToDataPoints(queryResponse);

          return {
            data: dataPoints,
            ...datasetOption,
          };
        })
      ),
    };

    return chartData;
  }

  return (
    <Graph
      getData={getData}
      drawer={
        <RateGraphDrawer
          reset={reset}
          duration={_duration}
          setDuration={setDuration}
          rate={_rate}
          setRate={setRate}
          resolution={_resolution}
          setResolution={setResolution}
          time={_time}
          setTime={setTime}
        />
      }
      options={options}
      boxProps={boxProps}
    />
  );
}

const executePreciseQuery = async (query: PrometheusPreciseQuery, rate: TimeDuration, duration: TimeDuration, resolution: TimeDuration, time: DateTime)=> {

  let updatedTime = time;
  if (updatedTime.hasSame(DateTime.now(), 'day')) {
    updatedTime = DateTime.now();
  }

  const dataResponse = await query_rate({
    metric: query.value,
    rate: rate,
    duration: duration,
    resolution: resolution,
    time: updatedTime,
  })

  const dataPoints = prometheusResultToDataPoints(dataResponse);

  const dataset = {
    data: dataPoints,
    ...query?.datasetOptions
  };

  return dataset
}

const executeGeneralQuery = async(query: PrometheusGeneralQuery, rate: TimeDuration, duration: TimeDuration, resolution: TimeDuration, time: DateTime) => {

  let updatedTime = time;
  if (updatedTime.hasSame(DateTime.now(), 'day')) {
    updatedTime = DateTime.now();
  }

  const dataResponse = await query_rate({
    metric: query.value,
    rate: rate,
    duration: duration,
    resolution: resolution,
    time: updatedTime,
  })


}
