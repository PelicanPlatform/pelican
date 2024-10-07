'use client';

import { Bar } from 'react-chartjs-2';
import { DateTime } from 'luxon';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset, Colors, Legend,
  LinearScale,
  LineElement,
  PointElement,
  TimeScale,
  Title,
  Tooltip,
  BarController,
  BarElement, ChartData,
} from 'chart.js';
import zoomPlugin from 'chartjs-plugin-zoom';

import { useContext, useEffect, useMemo, useState } from 'react';

import {GraphContext, GraphDispatchContext} from '@/app/origin/metrics/components/GraphContext';
import { query_raw, TimeDuration, VectorResponseData } from '@/components/graphs/prometheus';
import 'chartjs-adapter-luxon';
import useSWR from 'swr';
import { convertToBiggestBytes, toBytes } from '@/helpers/bytes';
import { average } from '@/helpers/util';

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
  BarController,
  BarElement
);

const TransferBarGraph = () => {

  const graphContext = useContext(GraphContext);
  const dispatch = useContext(GraphDispatchContext);

  const {data} = useSWR<ChartDataset<any, any>>(
    ['transferRateGraph', graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time],
    () => getData(graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time),
    {
      fallbackData: {datasets: []}
    }
  )

  return (
    <Bar
      data={data}
      options={{
        maintainAspectRatio: false,
        scales: {
          y: {
            type: "logarithmic",
            title: {
              display: true,
              text: `Transferred Bytes by Path (GB)`
            }
          }
        }
      }}
    />
  )
}

const getData = async (rate: TimeDuration, range: TimeDuration, resolution: TimeDuration, time: DateTime): Promise<ChartData<any, any, any>> => {

  const query = `sum by (path,type)(increase(xrootd_transfer_bytes[${range}]))`
  const dataResponse = await query_raw<VectorResponseData>(query, time.toSeconds())
  const result = dataResponse.data.result

  const datasets = result.reduce((acc, r) => {

    const path = r.metric.path
    const type = r.metric.type

    acc[path] = {
      ...acc?.[path],
      'path': path,
      [type]: Number(r.value[1])
    }

    return acc

  }, {} as Record<any, any>)

  return {
    labels: Object.keys(datasets),
    datasets: ['read', 'readv', 'write'].map((type) => {
      return {
        label: type,
        data: Object.values(datasets).map((d) => toBytes(d[type], "GB").value)
      }
    })
  }
}

export { TransferBarGraph };
