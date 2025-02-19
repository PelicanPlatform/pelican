'use client';
/**
 * Color bar indicating the uptime of servers as well as the number and time of restarts.
 *
 */
import {
  fillMatrixNulls,
  MatrixResponseData,
  MatrixResult,
  query_raw,
  replaceQueryParameters,
  TimeDuration,
  VectorResponseData,
} from '@/components';
import { useContext, useMemo } from 'react';
import { GraphContext } from '@/components/graphs/GraphContext';
import { DateTime } from 'luxon';
import { green, red } from '@mui/material/colors';
import { TimeBar } from '@chtc/web-components';
import { TimeBarProps, Point, Range } from '@chtc/web-components/dist/types';
import useSWR from 'swr';
import {
  Alert,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';

const ServerUptime = () => {
  const dispatch = useContext(AlertDispatchContext);
  const { rate, time, resolution, range } = useContext(GraphContext);

  let { data, error, isLoading, isValidating } = useSWR(
    ['pelican_director_server_count', rate, time, resolution, range],
    () =>
      alertOnError(
        () => getMetricData(rate, range, resolution, time),
        'Failed to fetch server uptime data from prometheus',
        dispatch,
        true
      ),
    {
      fallbackData: [],
    }
  );

  data = useMemo(() => (data ? data : []), [data]);

  return (
    <Box overflow={'scroll'} height={'100%'}>
      {data.length === 0 && !isLoading && !isValidating && (
        <Alert severity='warning'>No data available</Alert>
      )}
      <TableContainer>
        <Table size={'small'}>
          <TableHead>
            <TableRow>
              <TableCell>Server</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Restarts</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.map((d) => (
              <TableRow key={d.serverName}>
                <TableCell sx={{ maxWidth: '120px', overflow: 'hidden' }}>
                  {d.serverName}
                </TableCell>
                <TableCell>
                  <TimeBar
                    ranges={d.ranges}
                    points={d.points}
                    svgProps={{
                      width: '100%',
                      height: 20,
                    }}
                  />
                </TableCell>
                <TableCell>{d.points.length}</TableCell>
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
  ranges: Range[];
  points: Point[];
}

export const getMetricData = async (
  rate: TimeDuration,
  range: TimeDuration,
  resolution: TimeDuration,
  time: DateTime
): Promise<ServerUptimeData[]> => {
  const countQuery = replaceQueryParameters(
    'pelican_director_server_count[${range}:${resolution}]',
    {
      rate,
      range,
      resolution,
    }
  );
  const countResponse = await query_raw<MatrixResponseData>(
    countQuery,
    time.toSeconds()
  );

  const restartQuery = replaceQueryParameters(
    'process_start_time_seconds[${range}:${resolution}]',
    {
      range,
      resolution,
    }
  );
  const restartResponse = await query_raw<MatrixResponseData>(
    restartQuery,
    time.toSeconds()
  );

  const countResponseFilled = fillMatrixNulls(0, countResponse.data);

  let uptimes: ServerUptimeData[] = countResponseFilled.result.map((result) => {
    const serverName = result.metric.server_name;
    const ranges = countResponseToRanges(result);
    const restartServer = restartResponse.data.result.filter(
      (r) => r.metric.server_name === serverName
    );
    if (restartServer.length === 0) {
      return { serverName, ranges, points: [] };
    }

    return {
      serverName,
      ranges,
      points: restartResponseToPoints(restartServer[0]),
    };
  });

  return uptimes.sort((a, b) => {
    // Sort by the number of restarts
    return b.points.length - a.points.length;
  });
};

/** Our response will have value 0 or 1, bin together the values to reduce the number of data points */
const countResponseToRanges = (r: MatrixResult): Range[] => {
  // If there is a single data point, return a single range
  if (r.values.length === 1) {
    return [
      {
        start: r.values[0][0],
        end: r.values[0][0],
        fill: r.values[0][1] === '1' ? green[600] : red[600],
        title: r.values[0][1] === '1' ? 'Active' : 'Inactive',
      },
    ];
  }

  // Otherwise we can use the first value to determine the resolution length
  const resolution = r.values[1][0] - r.values[0][0];
  const ranges: Range[] = [];
  let activeRange: Range = {
    start: r.values[0][0] - resolution,
    end: r.values[0][0],
    fill: r.values[0][1] === '1' ? green[600] : red[600],
    title: r.values[0][1] === '1' ? 'Active' : 'Inactive',
  };

  r.values.slice(1, r.values.length).forEach(([n, v]) => {
    const currentState = activeRange?.fill === green[600] ? '1' : '0';
    if (v === currentState) {
      activeRange.end = n;
    } else {
      ranges.push(structuredClone(activeRange));
      activeRange = {
        start: n - resolution,
        end: n,
        fill: v === '1' ? green[600] : red[600],
        title: v === '1' ? 'Active' : 'Inactive',
      };
    }
  });

  ranges.push(activeRange);

  return ranges;
};

const restartResponseToPoints = (r: MatrixResult): Point[] => {
  const points: Point[] = [];
  let previousValue = r.values[0][1];
  r.values.forEach(([n, v]) => {
    if (v !== previousValue) {
      points.push({
        value: n,
        fill: 'black',
        title: 'Restart',
        onClick: (p) => {
          alert('Restart at ' + new Date(p.value * 1000).toLocaleString());
        },
      });
    }
    previousValue = v;
  });

  return points;
};

export default ServerUptime;
