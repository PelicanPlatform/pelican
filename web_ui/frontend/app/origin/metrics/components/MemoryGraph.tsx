'use client';

import { Line } from 'react-chartjs-2';
import { DateTime } from 'luxon';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset, Colors, Legend,
  LinearScale,
  LineElement,
  PointElement, TimeScale,
  Title,
  Tooltip,
} from 'chart.js';
import { useContext, useEffect, useState } from 'react';

import {GraphContext, GraphDispatchContext} from './GraphContext';
import { MatrixResponseData, query_raw, TimeDuration } from '@/components/graphs/prometheus';
import zoomPlugin from 'chartjs-plugin-zoom';
import 'chartjs-adapter-luxon';

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

  const [datasets, setDatasets] = useState<ChartDataset<any, any>>([])

  useEffect(() => {
    (async () => {
      const data = await getData(graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time)
      setDatasets(data)
    })()
  }, [graphContext])

  const data = {
    'datasets': datasets
  }

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
            },
          },
          y: {
            suggestedMax: 1000, // Set the minimum value for the y-axis
            title: {
              display: true,
              text: 'Memory Usage (MB)',
            }
          }
        },
        plugins: {
          legend: {
            display: false
          },
        }
      }}
    />
  )
}

const getData = async (rate: TimeDuration, range: TimeDuration, resolution: TimeDuration, time: DateTime): Promise<ChartDataset<any, any>> => {

  const query = `(go_memstats_alloc_bytes / 1024 / 1024)[${range}:${resolution}]`
  const dataResponse = await query_raw<MatrixResponseData>(query, time.toSeconds())
  const datasets = dataResponse.data.result.map((result) => {
    return {
      id: "Memory Usage",
      label: "Memory Usage (MB)",
      data: result.values.map((value) => {
        return {x: value[0] * 1000, y: parseFloat(value[1])}
      }),
      borderColor: 'green'
    }
  })

  return datasets
}

export { MemoryGraph };
