'use client';

/**
 * Large number display component
 * Includes a title, and large number display
 * Optionally superimposed over a line graph filled in with a color
 */

import React, { useContext, useEffect, useMemo, useState } from 'react';
import { Box, Typography, Grid } from '@mui/material';
import { Line } from 'react-chartjs-2';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset, Colors, Filler, Legend,
  LinearScale,
  LineElement,
  PointElement,
  TimeScale, Title, Tooltip,
} from 'chart.js';
import { default as chroma } from 'chroma-js';
import { GraphContext } from './GraphContext';
import { getRateDataFunction, getRateDataProps, MatrixResponseData, query_raw, VectorResponseData } from '@/components';
import zoomPlugin from 'chartjs-plugin-zoom';
import useSWR from 'swr';
import { convertToBiggestBytes, getSmallestByteCategory, toBytes } from '@/helpers/bytes';

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

interface BigNumberProps {
  title: string;
  value: string;
  color: string;
  data: DataPoint[];
}

interface DataPoint {
  x: number;
  y: number;
}

interface BigMetricProps {
  metric: string;
  finalType?: "sum" | "last";
  title: string;
  color: string;
}

export const BigMetric = ({metric, finalType = "sum", title, color = '#f3f3f3'}: BigMetricProps) => {

  const {rate, time, range, resolution} = useContext(GraphContext);

  const { data } = useSWR(
    ["getBigNumberData", metric, rate, time, range, resolution],
    () => getBigDataFunction({metric, rate, time, range, resolution}),
    {
      fallbackData: []
    }
  )

  const value = useMemo(() => {
    if(finalType === "sum") {
      return Math.ceil(data.reduce((acc: number, value: {x: number, y: number}) => acc + value.y, 0))
    } else {
      return data.length > 0 ? data[data.length - 1].y : 0
    }

  }, [data, finalType])

  return <BigNumber title={title} value={value.toLocaleString()} data={data} color={color}/>
}

export const BigBytesMetric = ({metric, title, finalType, color = '#f3f3f3'}: BigMetricProps) => {

  const {rate, time, range, resolution} = useContext(GraphContext);

  const { data } = useSWR(
    ["getBigNumberData", metric, rate, time, range, resolution],
    () => getBigDataFunction({metric, rate, time, range, resolution}),
    {
      fallbackData: []
    }
  )

  const dataSum = useMemo(() => {
    return Math.ceil(data.reduce((acc: number, value: {x: number, y: number}) => acc + value.y, 0))
  }, [data])

  const largestCompatibleByteValue = useMemo(() => {
    return convertToBiggestBytes(dataSum)
  }, [dataSum])

  const compatibleData =  useMemo(() => {

    let tempData = structuredClone(data)

    // Convert the array to the largest compatible byte category
    tempData.forEach((d) => {

      d.y = toBytes(d.y, largestCompatibleByteValue.label).value
    })

    return tempData

  }, [data, largestCompatibleByteValue])

  return <BigNumber data={compatibleData} title={`${title}`} value={`${largestCompatibleByteValue.value.toLocaleString()} ${largestCompatibleByteValue.label}`} color={color}/>
}


const BigNumber = ({title, value, data, color = '#f3f3f3'}: BigNumberProps) => {

  // Have the x-axis start at 0
  const zeroedData = useMemo(() => {
    return data.map((d) => {
      return {x: d.x - data[0].x, y: d.y}
    })
  }, [data])

  const chartData = {
    'datasets': [{
      label: "filled",
      data: zeroedData,
      backgroundColor: chroma(color).alpha(.8).hex(),
      borderColor: color,
      fill: true
    }]
  }

  return (
    <Box>
      <Box position={"absolute"} width="100%" bottom={0}>
        <Box p={3}>
          <Grid
            container
            spacing={2}
            direction="row"
            sx={{
              justifyContent: "space-between",
              alignItems: "center"
            }}
          >
            <Grid item>
              <Typography flexGrow={1} variant={"subtitle1"} fontWeight={"bold"}>{title}</Typography>
            </Grid>
            <Grid item>
              <Typography flexGrow={1} variant={"h4"} fontWeight={"bold"}>{value}</Typography>
            </Grid>
          </Grid>
        </Box>
      </Box>
      <Box>
        <Line
          data={chartData}
          options={{
            maintainAspectRatio: false,
            scales: {
              x: {
                type: 'time',
                time: {
                  round: 'second',
                },
                ticks: {
                  display: false
                },
                grid: {
                  color: 'rgba(0, 0, 0, 0.1)', // Lighter color for x-axis grid lines
                  lineWidth: 0.5, // Thinner grid lines
                },
              },
              y: {
                min: 0,
                ticks: {
                  display: false
                },
                grid: {
                  color: 'rgba(0, 0, 0, 0.1)', // Lighter color for y-axis grid lines
                  lineWidth: 0.5, // Thinner grid lines
                },
              }
            },
            plugins: {
              legend: {
                display: false
              },
              tooltip: {
                enabled: false // Disable tooltips
              }
            },
            animation: false
          }}
        />
      </Box>
    </Box>
  )
}

export interface getBigDataFunctionProps extends getRateDataProps {
  metric: string;
}

export const getBigDataFunction = async ({metric, rate, time, range, resolution}: getBigDataFunctionProps) : Promise<DataPoint[]> => {
  const query = `increase(${metric}[${resolution}])[${range}:${resolution}]`
  const dataResponse = await query_raw<MatrixResponseData>(query, time.toSeconds())

  // Check if the data is empty
  if (dataResponse.data.result.length == 0) {
    return []
  }

  // Otherwise parse the data
  const data = dataResponse.data.result[0].values.map(
    (value) => {
      return {x: value[0] * 1000, y: parseFloat(value[1])}
    }
  )

  return data
}

export { BigNumber };
