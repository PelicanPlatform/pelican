'use client';

import Link from 'next/link';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import { query_raw, VectorResponseData } from '@/components/graphs/prometheus';

import useSWR from 'swr';
import { useContext, useMemo } from 'react';
import { GraphContext } from '@/components/graphs/GraphContext';
import { DateTime } from 'luxon';
import chroma from 'chroma-js';
import { toBytesString } from '@/helpers/bytes';
import { ServerType } from '@/types';
import StyledTableCell from '@/components/StyledHeadTableCell';

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
        <TableContainer sx={{ maxHeight: '100%' }}>
          <Table stickyHeader size={'small'}>
            <TableHead>
              <TableRow>
                <StyledTableCell>Server</StyledTableCell>
                <StyledTableCell>Used ({totalUsedByteString})</StyledTableCell>
                <StyledTableCell>Free ({totalFreeByteString})</StyledTableCell>
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
                    <TableCell>
                      <Link
                        href={`/director/metrics/${d.serverType.toLowerCase()}/?server_name=${d.serverName}`}
                      >
                        {d.serverName}
                      </Link>
                    </TableCell>
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
      )}
    </>
  );
};

interface StorageMetric {
  serverName: string;
  serverType: ServerType;
  free: number;
  total: number;
}

const getStorageData = async (
  time: DateTime
): Promise<Record<string, StorageMetric>> => {
  const query = `xrootd_storage_volume_bytes`;
  const response = await query_raw<VectorResponseData>(query, time.toSeconds());

  const result = response.data.result;

  return result.reduce(
    (acc: Record<string, any>, r): Record<string, StorageMetric> => {
      const serverName = r.metric.server_name;
      const serverType = (r.metric?.server_type || 'Cache') as ServerType; // Default to Cache which subsets the Origin metrics
      const type = r.metric.type;

      if (serverName === undefined) {
        return acc;
      }

      acc[serverName] = {
        ...acc?.[serverName],
        [type]: Number(r.value[1]),
        serverName,
        serverType,
      };

      return acc;
    },
    {}
  );
};
