import { alertOnError } from '@/helpers/util';
import { useContext } from 'react';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { CellComponentProps, TableData } from '@/components/Table';
import DeleteCell from '@/components/Table/DeleteCell/DeleteCell';
import ConfirmButton from '@chtc/web-components/ConfirmButton';

interface MakeDeleteCellProps<R extends TableData> {
  mutate: () => void;
  handleDelete: (row: R) => Promise<void>;
  confirmButtonProps?: Partial<
    Omit<React.ComponentProps<typeof ConfirmButton>, 'onConfirm'>
  >;
}

function makeDeleteCell<R extends TableData>({
  mutate,
  handleDelete,
  confirmButtonProps,
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

    return (
      <DeleteCell
        handleDelete={cellHandleDelete}
        confirmButtonProps={confirmButtonProps}
      />
    );
  };

  DynamicDeleteCell.displayName = 'DeleteCell';

  return DynamicDeleteCell;
}

export default makeDeleteCell;
