'use client'

import { ChartDataset, ChartOptions } from 'chart.js';
import { useContext, useMemo } from 'react';
import { GraphContext } from '@/app/origin/metrics/components/GraphContext';
import useSWR from 'swr';
import { Chart } from 'react-chartjs-2';
import { query_raw, TimeDuration, VectorResponseData } from '@/components';
import { DateTime } from 'luxon';
import { toBytesString } from '@/helpers/bytes';
import { BoxplotToolTipItem } from '@/app/director/metrics/components/MetricBoxPlot';

export const CPUBoxPlot = ({options}: {options?: ChartOptions}) => {

  const {rate, time, resolution, range} = useContext(GraphContext);

  const {data} = useSWR(
    [rate, time, resolution, range],
    () => getMetricData(rate, range, resolution, time),
    {
      fallbackData: {data: [], labels: []}
    }
  )

  const chartData = useMemo(() => {
    return {
      labels: [`Core Usage`],
      datasets: [
        {
          label: `Core Usage`,
          data: [
            data.data
          ]
        }
      ]
    }
  }, [data])

  return (
    <Chart
      type='boxplot'
      data={chartData}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          tooltip: {
            callbacks: {
              label: function(context: BoxplotToolTipItem) {

                if(context.formattedValue.hoveredOutlierIndex !== -1){
                  let value = context.formattedValue.raw.outliers[context.formattedValue.hoveredOutlierIndex]
                  let dataIndex = chartData.datasets[0].data[0].indexOf(value)
                  let label = data.labels[dataIndex]
                  return `${label}: ${Math.round(value * 1000) / 1000}`
                }

                // Otherwise return the summary statistics
                const fv = context.formattedValue
                return `Q1: ${fv.q1} Mean: ${fv.mean} Median: ${fv.median} Q3: ${fv.q3}`
              }
            }
          }
        }
      }}
    />
  );
};

export const getMetricData = async (
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<{data: ChartDataset<any, any>, labels: string[]}> => {

  const query = `avg by (server_name) (irate(process_cpu_seconds_total[${range}]))`

  const dataResponse = await query_raw<VectorResponseData>(query, time.toSeconds())
  const result = dataResponse.data.result

  const data = result.map((result) => {
    return Number(result.value[1])
  })

  const labels = result.map((result) => {
    return result?.metric?.server_name || 'Missing Server Name'
  })

  return { data, labels }
}
