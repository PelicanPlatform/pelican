import { TableCell } from '@mui/material';
import { CellComponentProps } from '@/components/Table/types';

const DefaultCell = <R extends Record<string, any>, K extends keyof R>({
  row,
  value,
}: CellComponentProps<any, any>) => {
  return <TableCell>{value}</TableCell>;
};

export default DefaultCell;
