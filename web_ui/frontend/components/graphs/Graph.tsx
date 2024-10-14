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

import { useEffect, useRef, useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  TimeScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
  Colors,
} from 'chart.js';

import zoomPlugin from 'chartjs-plugin-zoom';
import 'chartjs-adapter-luxon';

import { BoxProps } from '@mui/material';

import { Line } from 'react-chartjs-2';
import { Box, Skeleton, Typography } from '@mui/material';

import { getDataWrapperFunction } from '@/components/graphs/prometheus';
import { ChartData } from 'chart.js';
import useSWR from 'swr';

const defaultOptions: Partial<ChartOptions<'line'>> = {
  scales: {
    x: {
      type: 'time',
      time: {
        round: 'second',
      },
    },
  },
};

interface GraphProps {
  getData: getDataWrapperFunction;
  drawer?: any;
  options?: ChartOptions<'line'>;
  boxProps?: BoxProps;
}

export default function Graph({
  getData,
  options,
  boxProps,
  drawer,
}: GraphProps) {
  const randomString = useRef<string>(Math.random().toString(36).substring(7));
  const { data, isLoading, error, mutate } = useSWR(
    'projectData' + randomString.current,
    getData
  );

  // Anytime the getter changes lets update the data accordingly
  useEffect(() => {
    mutate();
  }, [getData]);

  useEffect(() => {
    ChartJS.register(
      CategoryScale,
      LinearScale,
      PointElement,
      LineElement,
      Title,
      Tooltip,
      Legend,
      TimeScale,
      zoomPlugin,
      Colors
    );
  }, []);

  console.log(data);

  return (
    <Box>
      {isLoading || !data ? (
        <Box borderRadius={2} overflow={'hidden'}>
          <Skeleton variant={'rectangular'} width={'100%'} height={'300px'} />
        </Box>
      ) : (
        <>
          <Box m={'auto'} {...boxProps}>
            <Line
              data={data}
              options={{
                ...defaultOptions,
                ...options,
              }}
            />
          </Box>
          <Box display={'flex'}>{drawer ? drawer : undefined}</Box>
        </>
      )}
      {error && (
        <Box display={'flex'} flexDirection={'column'} pt={1}>
          <Typography
            m={'auto'}
            color={'red'}
            variant={'body2'}
            textAlign={'center'}
          >
            {JSON.stringify(error)}
          </Typography>
        </Box>
      )}
    </Box>
  );
}
