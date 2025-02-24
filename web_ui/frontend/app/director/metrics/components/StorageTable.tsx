'use client';

import {
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  MatrixResponseData,
  query_raw,
  TimeDuration,
  VectorResponseData,
} from '@/components/graphs/prometheus';

import useSWR from 'swr';
import { useContext, useMemo } from 'react';
import { GraphContext } from '@/components/graphs/GraphContext';
import { DateTime } from 'luxon';
import chroma from 'chroma-js';
import { convertToBiggestBytes, toBytes, toBytesString } from '@/helpers/bytes';

export const StorageTable = () => {
  const { rate, time, range, resolution } = useContext(GraphContext);

  const { data: storageData, error: projectError } = useSWR(
    ['projectData', time],
    () => getStorageData(time),
    {
      fallbackData: {},
    }
  );

  const totalFreeByteString = useMemo(() => {
    const freeBytes = Object.values(storageData).reduce(
      (acc, d) => acc + d.free,
      0
    );
    return toBytesString(freeBytes);
  }, [storageData]);

  const totalUsedByteString = useMemo(() => {
    const usedBytes = Object.values(storageData).reduce(
      (acc, d) => acc + (d.total - d.free),
      0
    );
    return toBytesString(usedBytes);
  }, [storageData]);

  const minFreeBytes = Math.min(
    ...Object.values(storageData).map((d) => d.free)
  );
  const maxFreeBytes = Math.max(
    ...Object.values(storageData).map((d) => d.free)
  );

  const minUsedBytes = Math.min(
    ...Object.values(storageData).map((d) => d.total - d.free)
  );
  const maxUsedBytes = Math.max(
    ...Object.values(storageData).map((d) => d.total - d.free)
  );

  return (
    <>
      {storageData !== undefined && (
        <Box overflow={'scroll'} height={'100%'}>
          <TableContainer>
            <Table size={'small'}>
              <TableHead>
                <TableRow>
                  <TableCell>Server</TableCell>
                  <TableCell>Used ({totalUsedByteString})</TableCell>
                  <TableCell>Free ({totalFreeByteString})</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Object.values(storageData)
                  .sort((a, b) => {
                    const nameA = a.serverName.toUpperCase();
                    const nameB = b.serverName.toUpperCase();
                    return nameA > nameB ? 1 : nameA < nameB ? -1 : 0;
                  })
                  .map((d) => (
                    <TableRow key={d.serverName}>
                      <TableCell>{d.serverName}</TableCell>
                      <TableCell
                        sx={{
                          bgcolor: chroma
                            .scale(['#f7f7f7', '#8bb7ff'])
                            .mode('lab')(
                              (d.total - d.free - minUsedBytes) /
                                (maxUsedBytes - minUsedBytes)
                            )
                            .hex(),
                        }}
                      >
                        {toBytesString(d.total - d.free)}
                      </TableCell>
                      <TableCell
                        sx={{
                          bgcolor: chroma
                            .scale(['#f7f7f7', '#8bb7ff'])
                            .mode('lab')(
                              (d.free - minFreeBytes) /
                                (maxFreeBytes - minFreeBytes)
                            )
                            .hex(),
                        }}
                      >
                        {toBytesString(d.free)}
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </>
  );
};

const getStorageData = async (
  time: DateTime
): Promise<
  Record<string, { serverName: string; free: number; total: number }>
> => {
  const query = `xrootd_storage_volume_bytes`;
  const response = await query_raw<VectorResponseData>(query, time.toSeconds());

  const result = response.data.result;

  return result.reduce((acc: Record<string, any>, r) => {
    const serverName = r.metric.server_name;
    const type = r.metric.type;

    if (serverName === undefined) {
      return acc;
    }

    acc[serverName] = {
      ...acc?.[serverName],
      serverName: serverName,
      [type]: Number(r.value[1]),
    };

    return acc;
  }, {});
};
