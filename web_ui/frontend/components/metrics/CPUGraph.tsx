'use client';

import { Line } from 'react-chartjs-2';
import { DateTime } from 'luxon';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset,
  Colors,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  TimeScale,
  Title,
  Tooltip,
} from 'chart.js';
import { useContext } from 'react';

import { GraphContext } from '@/components/graphs/GraphContext';
import {
  buildMetric,
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
  Colors,
  Filler
);

const CPUGraph = ({ server_name = undefined }: { server_name?: string }) => {
  const graphContext = useContext(GraphContext);

  const { data: datasets } = useSWR<ChartDataset<any, any>>(
    [
      'cpuGraph',
      server_name,
      graphContext.rate,
      graphContext.range,
      graphContext.resolution,
      graphContext.time,
    ],
    () =>
      getData(
        server_name,
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
            suggestedMax: 1, // Set the maximum value for the y-axis to 100%
            title: {
              display: true,
              text: 'CPU Usage by Core',
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
  server_name: string | undefined,
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<ChartDataset<any, any>> => {
  const metric = buildMetric('process_cpu_seconds_total', { server_name });
  const query = `avg by (instance) (irate(${metric}[${rate}]))[${range}:${resolution}]`;
  const dataResponse = await query_raw<MatrixResponseData>(
    query,
    time.toSeconds()
  );
  const datasets = dataResponse.data.result.map((result) => {
    return {
      id: 'CPU Usage By Core',
      label: 'CPU Usage By Core',
      data: result.values.map((value) => {
        return {
          x: value[0] * 1000,
          y: parseFloat(value[1]),
        };
      }),
    };
  });

  return datasets;
};

export { CPUGraph };
