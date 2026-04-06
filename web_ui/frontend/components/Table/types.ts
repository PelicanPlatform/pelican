export interface SortState<K extends string = string> {
  columnId: K;
  direction: 'asc' | 'desc';
}

export interface ColumnConfig<R extends TableData> {
  id: keyof R & string;
  name: string;
  value?: (r: R) => any;
  sort?: (a: R[keyof R], b: R[keyof R]) => number;
  onSort?: ({ columnId, direction }: SortState) => void;
  CellComponent?: React.FC<CellComponentProps<R, keyof R>>;
}

export interface ActionConfig<R extends TableData> {
  id: string;
  name: string;
  value?: (r: R) => any;
  onClick: (r: R) => void;
  CellComponent?: React.FC<CellComponentProps<R, any>>;
}

export type CellComponentProps<R extends TableData, K extends keyof R> = {
  row: R;
  value: R[K];
};

export type TableData = Record<string, any>;

export interface ClientTableImplementationProps<R extends TableData> {
  data: R[];
  mutate: () => void;
  columns?: Record<string, ColumnConfig<R>>;
}
