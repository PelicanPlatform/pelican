import React, { ReactElement, useMemo } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';

export interface ColumnMap {
  [key: string]: Column;
}

export interface Column {
  name: string;
  cellNode: React.JSX.ElementType;
}

export interface Record {
  [key: string]: string | number | boolean | null;
}

const DataTable = ({
  columnMap,
  data,
}: {
  columnMap: ColumnMap;
  data: Record[];
}): ReactElement => {
  // If there is data then show, if not then indicate no data
  const rows = useMemo(() => {
    if (data.length !== 0) {
      return data.map((record, index) => (
        <TableRow key={index}>
          {Object.entries(columnMap).map(([key, column], index) => {
            const CellNode = column.cellNode;
            return <CellNode key={index}>{record[key]}</CellNode>;
          })}
        </TableRow>
      ));
    } else {
      return (
        <TableRow>
          {Object.entries(columnMap).map(([key, column], index) => {
            return <TableCell key={index}>No Data</TableCell>;
          })}
        </TableRow>
      );
    }
  }, [data]);

  return (
    <TableContainer sx={{ maxHeight: '500px' }}>
      <Table stickyHeader={true} sx={{ tableLayout: 'fixed' }}>
        <TableHead>
          <TableRow>
            {Object.values(columnMap).map((column, index) => (
              <TableCell key={index}>{column.name}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>{rows}</TableBody>
      </Table>
    </TableContainer>
  );
};

export default DataTable;
