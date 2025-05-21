'use client';

/**
 * Storage graph component
 *
 * Display the current storage usage and free space with a pie graph
 */

import { Doughnut } from 'react-chartjs-2';

import { useContext } from 'react';
import { DateTime } from 'luxon';
import { ArcElement, Chart as ChartJS, Colors, Title, Tooltip } from 'chart.js';
import { blue, grey } from '@mui/material/colors';

import { GraphContext } from '@/components/graphs/GraphContext';
import {
  buildMetric,
  query_raw,
  VectorResponseData,
} from '@/components/graphs/prometheus';

import useSWR from 'swr';
import { convertListBytes } from '@/helpers/bytes';

ChartJS.register(Title, Tooltip, Colors, ArcElement);

interface storageData {
  used: number;
  free: number;
}

const StorageGraph = ({
  server_name = undefined,
}: {
  server_name?: string;
}) => {
  const graphContext = useContext(GraphContext);

  const { data } = useSWR<storageData>(
    ['getStorageData', graphContext.time, server_name],
    () => getStorageData(server_name, graphContext.time.toSeconds())
  );

  const [usedBytes, freeBytes] = convertListBytes([
    data?.used ?? 0,
    data?.free ?? 0,
  ]);

  const dataConvert = {
    used: usedBytes,
    free: freeBytes,
  };

  const dataset = {
    labels: [
      `Used (${Math.round(dataConvert.used.value * 100) / 100} ${dataConvert.used.label})`,
      `Free (${Math.round(dataConvert.free.value * 100) / 100} ${dataConvert.free.label})`,
    ],
    datasets: [
      {
        data: [dataConvert?.used.value ?? 0, dataConvert?.free.value ?? 0],
        backgroundColor: [blue[300], grey[50]],
        borderColor: [blue[500], grey[300]],
      },
    ],
  };

  return (
    <Doughnut
      data={dataset}
      options={{
        maintainAspectRatio: false,
      }}
    />
  );
};

const getStorageData = async (
  server_name: string | undefined,
  time: number = DateTime.now().toSeconds()
): Promise<{ free: number; used: number }> => {
  const metric = buildMetric('xrootd_storage_volume_bytes', {
    server_type: 'origin',
    server_name,
  });
  const url = `sum by (type) (${metric})`;
  const response = await query_raw<VectorResponseData>(url, time);

  const result = response.data.result;

  // We know one will be of type 'free' and the other 'total'
  const free =
    Number(result.find((r) => r.metric.type === 'free')?.value[1]) ?? 0;
  const total =
    Number(result.find((r) => r.metric.type === 'total')?.value[1]) ?? 0;
  const used = total - free;

  return { free, used };
};

export { StorageGraph };
