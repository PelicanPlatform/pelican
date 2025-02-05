'use client';

import Link from 'next/link';
import { Chart } from 'react-chartjs-2';
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
  LogarithmicScale,
  ChartOptions,
  TooltipLabelStyle,
  TooltipItem,
} from 'chart.js';
import { getRelativePosition } from 'chart.js/helpers';
import { useContext, useEffect, useMemo, useState } from 'react';
import {
  BoxAndWiskers,
  BoxPlotController,
} from '@sgratzl/chartjs-chart-boxplot';
import {
  MatrixResponseData,
  query_raw,
  replaceQueryParameters,
  TimeDuration,
  VectorResponseData,
} from '@/components';
import { DateTime } from 'luxon';
import {
  GraphContext,
  GraphDispatchContext,
} from '@/components/graphs/GraphContext';
import useSWR from 'swr';
import {
  getSmallestByteCategory,
  toBytes,
  toBytesString,
} from '@/helpers/bytes';
import { evaluateOrReturn, TypeOrTypeFunction } from '@/helpers/util';
import { useRouter } from 'next/navigation';

ChartJS.register(
  BoxPlotController,
  BoxAndWiskers,
  TimeScale,
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Colors,
  Filler
);

export const BytesMetricBoxPlot = ({
  metric,
  title,
  options,
}: {
  metric: string;
  title: string;
  options?: ChartOptions;
}) => {
  const router = useRouter();
  const { rate, time, resolution, range } = useContext(GraphContext);

  const { data } = useSWR(
    [metric, rate, time, resolution, range],
    () => getMetricData(metric, rate, range, resolution, time),
    {
      fallbackData: { data: [], labels: [] },
    }
  );

  const compatibleByteData = useMemo(() => {
    return getSmallestByteCategory(data.data);
  }, [data]);

  const chartData = useMemo(() => {
    return {
      labels: [`${title} (${compatibleByteData})`],
      datasets: [
        {
          label: title,
          data: [
            data.data.map((d: number) => toBytes(d, compatibleByteData).value),
          ],
          color: function (context: any) {
            var index = context.dataIndex;
            var value = context.dataset.data[index];
            return value < 0
              ? 'red' // draw negative values in red
              : index % 2
                ? 'blue' // else, alternate values in blue and green
                : 'green';
          },
        },
      ],
    };
  }, [data]);

  return (
    <Chart
      type='boxplot'
      data={chartData}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            type: 'logarithmic',
          },
        },
        onClick: function (evt: any, item: any) {
          if (item.length === 0) {
            return;
          }
          const position = getRelativePosition(evt, evt.Chart) as any; // Typing is wrong
          try {
            const serverName =
              position.chart.tooltip.body[0].lines[0].split(':')[0];
            if (serverName != 'Missing Server Name') {
              router.push(
                '/director/metrics/origin/?server_name=' +
                  position.chart.tooltip.body[0].lines[0].split(':')[0]
              );
            }
          } catch {}
        },
        plugins: {
          tooltip: {
            callbacks: {
              label: function (context: BoxplotToolTipItem) {
                if (context.formattedValue.hoveredOutlierIndex !== -1) {
                  let value =
                    context.formattedValue.raw.outliers[
                      context.formattedValue.hoveredOutlierIndex
                    ];
                  let dataIndex = chartData.datasets[0].data[0].indexOf(value);
                  let label = data.labels[dataIndex];
                  return `${label}: ${toBytesString(data.data[dataIndex], compatibleByteData)}`;
                }

                // Otherwise return the summary statistics
                const fv = context.formattedValue;
                return `Q1: ${fv.q1} Mean: ${fv.mean} Median: ${fv.median} Q3: ${fv.q3}`;
              },
            },
          },
        },
      }}
    />
  );
};

export const MetricBoxPlot = ({
  metric,
  title,
  options,
}: {
  metric: string;
  title: string;
  options?: ChartOptions;
}) => {
  const router = useRouter();
  const { rate, time, resolution, range } = useContext(GraphContext);

  const { data } = useSWR(
    [metric, rate, time, resolution, range],
    () => getMetricData(metric, rate, range, resolution, time),
    {
      fallbackData: { data: [], labels: [] },
    }
  );

  const chartData = useMemo(() => {
    return {
      labels: [`${title}`],
      datasets: [
        {
          label: title,
          data: [data.data],
        },
      ],
    };
  }, [data]);

  return (
    <Chart
      type='boxplot'
      data={chartData}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            type: 'logarithmic',
          },
        },
        onClick: function (evt: any, item: any) {
          if (item.length === 0) {
            return;
          }
          const position = getRelativePosition(evt, evt.Chart) as any; // Typing is broken here for the Chartjs library
          try {
            const serverName =
              position.chart.tooltip.body[0].lines[0].split(':')[0];
            if (serverName != 'Missing Server Name') {
              router.push(
                '/director/metrics/origin/?server_name=' +
                  position.chart.tooltip.body[0].lines[0].split(':')[0]
              );
            }
          } catch {}
        },
        plugins: {
          tooltip: {
            callbacks: {
              label: function (context: BoxplotToolTipItem) {
                if (context.formattedValue.hoveredOutlierIndex !== -1) {
                  let value =
                    context.formattedValue.raw.outliers[
                      context.formattedValue.hoveredOutlierIndex
                    ];
                  let dataIndex = chartData.datasets[0].data[0].indexOf(value);
                  let label = data.labels[dataIndex];
                  return `${label}: ${Math.round(value)}`;
                }

                // Otherwise return the summary statistics
                const fv = context.formattedValue;
                return `Q1: ${fv.q1} Mean: ${fv.mean} Median: ${fv.median} Q3: ${fv.q3}`;
              },
            },
          },
        },
      }}
    />
  );
};

export const getMetricData = async (
  metric: string,
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<{ data: ChartDataset<any, any>; labels: string[] }> => {
  const query = replaceQueryParameters(metric, {
    metric,
    rate,
    range,
    resolution,
  });

  const dataResponse = await query_raw<VectorResponseData>(
    query,
    time.toSeconds()
  );
  const result = dataResponse.data.result;

  const data = result.map((result) => {
    return Number(result.value[1]);
  });

  const labels = result.map((result) => {
    return result?.metric?.server_name || 'Missing Server Name';
  });

  return {
    data,
    labels,
  };
};

export type BoxplotToolTipItem = TooltipItem<'boxplot'> & {
  formattedValue: {
    raw: {
      outliers: number[];
    };
    hoveredOutlierIndex: number;
    q1: number;
    mean: number;
    median: number;
    q3: number;
  };
};
