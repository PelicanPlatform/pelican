'use client';

import { Line } from 'react-chartjs-2';
import { DateTime } from 'luxon';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset, Colors, Filler, Legend,
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

const CPUGraph = () => {

  const graphContext = useContext(GraphContext);

  const {data: datasets} = useSWR<ChartDataset<any, any>>(
    ['cpuGraph', graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time],
    () => getData(graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time),
    {
      fallbackData: []
    }
  )

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
            suggestedMax: 1, // Set the maximum value for the y-axis to 100%
            title: {
              display: true,
              text: 'CPU Usage by Core'
            }
          },
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

  const query = `avg by (instance) (irate(process_cpu_seconds_total[${rate}]))[${range}:${resolution}]`
  const dataResponse = await query_raw<MatrixResponseData>(query, time.toSeconds())
  const datasets = dataResponse.data.result.map((result) => {
    return {
      id: "CPU Usage By Core",
      label: "CPU Usage By Core",
      data: result.values.map((value) => {
        return {
          x: value[0] * 1000,
          y: parseFloat(value[1])
        }
      })
    }
  })

  return datasets
}

export { CPUGraph };
