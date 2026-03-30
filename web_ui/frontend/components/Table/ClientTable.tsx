import Table from './Table';
import { ColumnConfig, SortState, TableData, ActionConfig } from '@/components/Table/types';
import {useState} from "react";
import {DEFAULT_PAGE_SIZE_OPTIONS} from "@/components/Table/constants";


type ClientColumnConfig<R extends TableData> = Omit<ColumnConfig<R>, 'onSort'>;

export interface ClientTableProps<R extends TableData> {
  data: R[];
  columns: Record<string, ClientColumnConfig<R> | ActionConfig<R>>;
  defaultSort?: SortState<keyof R & string>;
  pagination?: boolean
}

const ClientTable = <R extends TableData>({
  data,
  columns,
  defaultSort
}: ClientTableProps<R>) => {

  // Manage sort state locally since this is a client component
  const [sort, setSort] = useState<SortState<keyof R & string> | undefined>(defaultSort || undefined);
  const sortColumn = sort && columns[sort.columnId] as ClientColumnConfig<R>;
  const sortHandler = sortColumn ? sortColumn.sort : null;
  const sortedData = sortHandler && sort ? [...data].sort((a, b) => sortHandler(a[sort.columnId], b[sort.columnId]) * (sort.direction === 'asc' ? 1 : -1)) : data;

  // Manage pagination state
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE_OPTIONS[0]);
  const enablePagination = data.length > pageSize;

  // Add onSort handlers to columns that have sorting enabled
  const sortableColumns = Object.values(columns).map((column) => {
    if ('sort' in column && column.sort) {
      return {
        ...column,
        onSort: ({ columnId, direction }: SortState) => {
          setSort({ columnId, direction });
        },
      };
    }
    return column;
  })

  // If pagination is enabled, slice the sorted data to get only the current page's data
  const paginatedData = enablePagination ? sortedData.slice(page * pageSize, page * pageSize + pageSize) : sortedData;

  return <Table
    data={paginatedData}
    columns={sortableColumns}
    sort={sort}
    pagination={enablePagination ? {
      totalCount: data.length,
      page,
      pageSize,
      onPageChange: (newPage) => setPage(newPage),
      onPageSizeChange: (newPageSize) => {
        setPageSize(newPageSize);
        setPage(0); // Reset to first page when page size changes
      }
    } : undefined}
  />;
}

export default ClientTable;
