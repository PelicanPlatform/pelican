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
              <TableCell>Restarts</TableCell>
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
                <TableCell>{d.restarts}</TableCell>
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
  restarts: number;
}

export const getMetricData = async (
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<ServerUptimeData[]> => {

  const countQuery = replaceQueryParameters('pelican_director_server_count[${range}:${resolution}]', {
    rate,
    range,
    resolution,
  });
  const countResponse = await query_raw<MatrixResponseData>(
    countQuery,
    time.toSeconds()
  );

  const restartQuery = replaceQueryParameters('changes(process_start_time_seconds[${range}])', {
    range
  })
  const restartResponse = await query_raw<VectorResponseData>(
    restartQuery,
    time.toSeconds()
  );

  let uptimes: ServerUptimeData[] = countResponse.data.result.map((result) => {
    const serverName = result.metric.server_name;
    const downtime = result.values.map((value) => value[1] === '1');
    const restartServer = restartResponse.data.result
      .filter((r) => r.metric.server_name === serverName)
    if (restartServer.length === 0) {
      return { serverName, downtime, restarts: 0 };
    }

    return { serverName, downtime, restarts: parseInt(restartServer[0].value[1]) };
  });

  let maxLength = Math.max(...uptimes.map((u) => u.downtime.length));

  uptimes = uptimes.map((u) => {
    let downtime = u.downtime;
    while (downtime.length < maxLength) {
      downtime.unshift(undefined);
    }
    return { serverName: u.serverName, downtime, restarts: u.restarts };
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
