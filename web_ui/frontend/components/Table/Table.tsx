import {
  TableCell,
  TableContainer,
  TableHead,
  Table as MUITable,
  TableSortLabel,
  Box,
  TableBody,
  TableRow,
  TablePagination,
} from '@mui/material';

import DefaultCell from './DefaultCell';
import {
  ActionConfig,
  ColumnConfig,
  TableData,
} from '@/components/Table/types';
import { DEFAULT_PAGE_SIZE_OPTIONS } from '@/components/Table/constants';

export interface TableProps<R extends TableData> {
  data: R[];
  columns: (ColumnConfig<R> | ActionConfig<R>)[];
  sort?: { columnId: keyof R; direction: 'asc' | 'desc' };
  pagination?: {
    totalCount: number;
    page: number;
    pageSize?: number;
    onPageChange: (newPage: number) => void;
    onPageSizeChange: (newRowsPerPage: number) => void;
  };
}

const Table = <R extends TableData>(props: TableProps<R>) => {
  const { data, columns, sort, pagination } = props;

  return (
    <TableContainer>
      <MUITable>
        <TableHead>
          <TableRow>
            {columns.map((column, colIndex) => {
              return (
                <TableCell
                  key={String(colIndex)}
                  sortDirection={
                    sort?.columnId === column.id ? sort.direction : false
                  }
                  onClick={() =>
                    'onSort' in column &&
                    column.onSort &&
                    column.onSort({
                      columnId: column.id,
                      direction: sort?.direction == 'asc' ? 'desc' : 'asc',
                    })
                  }
                >
                  <TableSortLabel
                    hideSortIcon={!('sort' in column && column.sort !== null)}
                    active={sort?.columnId === column.id}
                    direction={sort?.direction}
                  >
                    {column.name}
                    {sort?.columnId === column.id ? (
                      <Box component='span' sx={{ display: 'none' }}>
                        {sort?.direction === 'desc'
                          ? 'sorted descending'
                          : 'sorted ascending'}
                      </Box>
                    ) : null}
                  </TableSortLabel>
                </TableCell>
              );
            })}
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((row, rowIndex) => (
            <TableRow key={`${pagination ? pagination.page : 0}-${rowIndex}`}>
              {columns.map((column, colIndex) => {
                const CellComponent = column.CellComponent || DefaultCell;
                const value = column.value ? column.value(row) : row[column.id];
                return (
                  <CellComponent
                    key={`${rowIndex}-${colIndex}`}
                    row={row}
                    value={value}
                  />
                );
              })}
            </TableRow>
          ))}
        </TableBody>
      </MUITable>

      {pagination !== undefined ? (
        <TablePagination
          component='div'
          count={pagination.totalCount}
          page={pagination.page}
          onPageChange={(event, newPage) => pagination.onPageChange(newPage)}
          rowsPerPage={pagination.pageSize || DEFAULT_PAGE_SIZE_OPTIONS[0]}
          onRowsPerPageChange={(event) =>
            pagination.onPageSizeChange(parseInt(event.target.value, 10))
          }
          rowsPerPageOptions={DEFAULT_PAGE_SIZE_OPTIONS}
        />
      ) : null}
    </TableContainer>
  );
};

export default Table;
