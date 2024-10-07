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
import zoomPlugin from 'chartjs-plugin-zoom';

import { useContext, useEffect, useMemo, useState } from 'react';

import {GraphContext, GraphDispatchContext} from './GraphContext';
import { MatrixResponseData, query_raw, TimeDuration } from '@/components/graphs/prometheus';
import 'chartjs-adapter-luxon';
import useSWR from 'swr';
import { ByteType, convertToBiggestBytes, toBytes } from '@/helpers/bytes';
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
  Colors
);

const TransferRateGraph = () => {

  const graphContext = useContext(GraphContext);
  const dispatch = useContext(GraphDispatchContext);

  const {data: datasets} = useSWR<ChartDataset<'line', { x: number; y: number }[]>[]>(
    ['transferRateGraph', graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time],
    () => getData(graphContext.rate, graphContext.range, graphContext.resolution, graphContext.time),
    {
      fallbackData: []
    }
  )

  const byteLabel = useMemo(() => {
    if(datasets){
      return convertToBiggestBytes(average(datasets.flatMap(ds => ds.data).map(d => d.y))).label
    }
  }, [datasets])

  const byteDatasets = useMemo((): ChartDataset<'line', { x: number; y: number }[]>[] => {
    if(datasets !== undefined && byteLabel !== undefined) {
      return toBytesDataset(datasets, byteLabel)
    }
    return []
  }, [datasets, byteLabel])

  const data = {
    'datasets': byteDatasets
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
            title: {
              display: true,
              text: `Transfer Rate (${byteLabel}/s)`
            }
          }
        },
        plugins: {
          legend: {
            display: false
          },
          zoom: {
            zoom: {
              drag: {
                enabled: true,
              },
              pinch: {
                enabled: true
              },
              mode: 'x',
              onZoom: (event) => {
                dispatch({
                  type: "setTimeRange",
                  payload: {
                    start: DateTime.fromMillis(event.chart.scales.x.min),
                    end: DateTime.fromMillis(event.chart.scales.x.max)
                  }
                })
              }
            }
          }
        }
      }}
    />
  )
}

const toBytesDataset = (datasets: ChartDataset<'line', { x: number; y: number }[]>[], byteLabel: ByteType): ChartDataset<'line', { x: number; y: number }[]>[]  => {
  let byteDatasets = structuredClone(datasets)

  return byteDatasets.map((ds) => {
    return {
      ...ds,
      data: ds.data.map((d) => {
        return {
          ...d,
          y: toBytes(d.y, byteLabel).value
        }
      })
    }
  })
}

const getData = async (rate: TimeDuration, range: TimeDuration, resolution: TimeDuration, time: DateTime): Promise<ChartDataset<'line', { x: number; y: number }[]>[]> => {

  const query = `sum by (path, type) (rate(xrootd_transfer_bytes[${rate}]))[${range}:${resolution}]`
  const dataResponse = await query_raw<MatrixResponseData>(query, time.toSeconds())
  const datasets = dataResponse.data.result.map((result) => {
    return {
      id: result.metric?.path,
      label: `${result.metric?.type} -> ${result.metric?.path}`,
      data: result.values.map((value) => {
        return {x: value[0] * 1000, y: parseFloat(value[1])}
      })
    }
  })

  // Filter out the datasets that have no data
  const filteredDatasets = datasets.filter((dataset) => isDataPresent(dataset.data))

  return filteredDatasets
}

const isDataPresent = (data: {x: any, y: number}[]) => {

  return data.map((data) => data.y != 0).includes(true)
}

export { TransferRateGraph };
