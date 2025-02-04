'use client';
/**
 * Bar graph displaying the number of servers that are active indicating the inactive ones
 *
 */
import {
  MatrixResponseData,
  query_raw,
  replaceQueryParameters,
  TimeDuration,
  VectorResponseData,
} from '@/components';
import { useContext, useMemo } from 'react';
import { GraphContext } from '@/components/graphs/GraphContext';
import { DateTime } from 'luxon';
import { ChartDataset, ChartData } from 'chart.js';
import { DowntimeBar } from '@chtc/web-components';
import useSWR from 'swr';
import {
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import chroma from 'chroma-js';
import { toBytesString } from '@/helpers/bytes';

const ServerUptime = () => {
  const { rate, time, resolution, range } = useContext(GraphContext);

  const { data } = useSWR(
    ['pelican_director_server_count', rate, time, resolution, range],
    () =>
      getMetricData(
        'pelican_director_server_count[${range}:${resolution}]',
        rate,
        range,
        resolution,
        time
      ),
    {
      fallbackData: [],
    }
  );

  return (
    <Box overflow={'scroll'} height={'100%'}>
      <TableContainer>
        <Table size={'small'}>
          <TableHead>
            <TableRow>
              <TableCell>Server</TableCell>
              <TableCell>Downtime</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.map((d) => (
              <TableRow key={d.serverName}>
                <TableCell>{d.serverName}</TableCell>
                <TableCell>
                  <DowntimeBar
                    data={d.downtime}
                    height={'20px'}
                    width={'150px'}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

interface ServerUptimeData {
  serverName: string;
  downtime: (boolean | undefined)[];
}

export const getMetricData = async (
  metric: string,
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<ServerUptimeData[]> => {
  const query = replaceQueryParameters(metric, {
    metric,
    rate,
    range,
    resolution,
  });

  const dataResponse = await query_raw<MatrixResponseData>(
    query,
    time.toSeconds()
  );

  let uptimes: ServerUptimeData[] = dataResponse.data.result.map((result) => {
    const serverName = result.metric.server_name;
    const downtime = result.values.map((value) => value[1] === '1');
    return { serverName, downtime };
  });

  let maxLength = Math.max(...uptimes.map((u) => u.downtime.length));

  uptimes = uptimes.map((u) => {
    let downtime = u.downtime;
    while (downtime.length < maxLength) {
      downtime.unshift(undefined);
    }
    return { serverName: u.serverName, downtime };
  });

  return uptimes.sort((a, b) => {
    // Sort by the number of downtimes with the most downtimes first
    return (
      a.downtime.reduce((acc, d) => acc + (d ? 1 : 0), 0) -
      b.downtime.reduce((acc, d) => acc + (d ? 1 : 0), 0)
    );
  });
};

export default ServerUptime;
