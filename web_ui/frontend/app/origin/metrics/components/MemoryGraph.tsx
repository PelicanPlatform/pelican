'use client';

import { Line } from 'react-chartjs-2';
import { DateTime } from 'luxon';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset,
  Colors,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  TimeScale,
  Title,
  Tooltip,
} from 'chart.js';
import { useContext, useEffect, useState } from 'react';

import {
  GraphContext,
  GraphDispatchContext,
} from '@/components/graphs/GraphContext';
import {
  MatrixResponseData,
  query_raw,
  TimeDuration,
} from '@/components/graphs/prometheus';
import zoomPlugin from 'chartjs-plugin-zoom';
import 'chartjs-adapter-luxon';
import useSWR from 'swr';

ChartJS.register(
  TimeScale,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  zoomPlugin,
  Colors
);

const MemoryGraph = () => {
  const graphContext = useContext(GraphContext);

  const { data: datasets } = useSWR<ChartDataset<any, any>>(
    [
      'memoryGraph',
      graphContext.rate,
      graphContext.range,
      graphContext.resolution,
      graphContext.time,
    ],
    () =>
      getData(
        graphContext.rate,
        graphContext.range,
        graphContext.resolution,
        graphContext.time
      ),
    {
      fallbackData: [],
    }
  );

  const data = {
    datasets: datasets,
  };

  return (
    <Line
      data={data}
      options={{
        maintainAspectRatio: false,
        scales: {
          x: {
            type: 'time',
            time: {
              round: 'second',
              displayFormats: {
                millisecond: 'LLL d, HH:mm, HH:mm',
                second: 'LLL d, HH:mm',
                minute: 'LLL d, HH:mm',
                hour: 'LLL d, HH:mm',
                day: 'LLL d, HH:mm',
                week: 'LLL d, HH:mm',
                month: 'LLL d, HH:mm',
                quarter: 'LLL d, HH:mm',
                year: 'LLL d, HH:mm',
              },
            },
          },
          y: {
            suggestedMax: 1000, // Set the minimum value for the y-axis
            title: {
              display: true,
              text: 'Memory Usage (MB)',
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
        },
      }}
    />
  );
};

const getData = async (
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<ChartDataset<any, any>> => {
  const query = `(go_memstats_alloc_bytes / 1024 / 1024)[${range}:${resolution}]`;
  const dataResponse = await query_raw<MatrixResponseData>(
    query,
    time.toSeconds()
  );
  const datasets = dataResponse.data.result.map((result) => {
    return {
      id: 'Memory Usage',
      label: 'Memory Usage (MB)',
      data: result.values.map((value) => {
        return { x: value[0] * 1000, y: parseFloat(value[1]) };
      }),
      borderColor: 'green',
    };
  });

  return datasets;
};

export { MemoryGraph };
