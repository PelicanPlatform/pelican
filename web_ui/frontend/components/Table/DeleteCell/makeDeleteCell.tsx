import { alertOnError } from '@/helpers/util';
import { useContext } from 'react';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { CellComponentProps, TableData } from '@/components/Table';
import DeleteCell from '@/components/Table/DeleteCell/DeleteCell';

interface MakeDeleteCellProps<R extends TableData> {
  mutate: () => void;
  handleDelete: (row: R) => Promise<void>;
}

function makeDeleteCell<R extends TableData>({
  mutate,
  handleDelete,
}: MakeDeleteCellProps<R>) {
  const DynamicDeleteCell = ({ row }: CellComponentProps<R, any>) => {
    const dispatch = useContext(AlertDispatchContext);

    const cellHandleDelete = async () => {
      try {
        await alertOnError(
          () => handleDelete(row),
          `Error Deleting Item`,
          dispatch,
          true
        );
        mutate();
      } catch {}
    };

    return <DeleteCell handleDelete={cellHandleDelete} />;
  };

  DynamicDeleteCell.displayName = 'DeleteCell';

  return DynamicDeleteCell;
}

export default makeDeleteCell;
