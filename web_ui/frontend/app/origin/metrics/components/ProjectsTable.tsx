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
import { useContext } from 'react';
import { GraphContext } from '@/components/graphs/GraphContext';
import { DateTime } from 'luxon';
import { convertToBiggestBytes } from '@/helpers/bytes';

interface ProjectData {
  name: string;
  bytesAccessed: string;
}

export const ProjectTable = () => {
  const { rate, time, range, resolution } = useContext(GraphContext);

  const { data: projectData, error: projectError } = useSWR(
    ['projectData', time, range],
    () => getProjectData(range, time)
  );

  return (
    <>
      {projectData !== undefined && (
        <Box overflow={'scroll'} height={'100%'}>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Project</TableCell>
                  <TableCell>Bytes Accessed</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {projectData.map((project) => (
                  <TableRow key={project.name}>
                    <TableCell>{project.name}</TableCell>
                    <TableCell>
                      {project.bytesAccessed.toLocaleString()}
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

const getProjectData = async (
  range: TimeDuration,
  time: DateTime
): Promise<ProjectData[]> => {
  const queryResponse = await query_raw<VectorResponseData>(
    `sum by (proj) (increase(xrootd_transfer_bytes{type!="write", proj!=""}[${range}]))`,
    time.toSeconds()
  );
  const result = queryResponse.data.result;

  // Sort the result
  result.sort((a, b) => {
    return Number(b.value[1]) - Number(a.value[1]);
  });

  const projectData = result.map((result) => {
    const bytes = convertToBiggestBytes(Number(result.value[1]));

    return {
      name: result.metric?.proj,
      bytesAccessed: `${Math.round(bytes.value).toLocaleString()} ${bytes.label}`,
    };
  });

  return projectData;
};
