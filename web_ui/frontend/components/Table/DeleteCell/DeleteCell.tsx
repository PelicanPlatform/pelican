import ConfirmButton from '@chtc/web-components/ConfirmButton';
import { TableCell } from '@mui/material';
import { Delete } from '@mui/icons-material';

interface DeleteCellProps {
  handleDelete: () => void;
  confirmButtonProps?: Partial<
    Omit<React.ComponentProps<typeof ConfirmButton>, 'onConfirm'>
  >;
}

const DeleteCell = ({ handleDelete, confirmButtonProps }: DeleteCellProps) => {
  return (
    <TableCell>
      <ConfirmButton
        color={'error'}
        onConfirm={handleDelete}
        aria-label={'Delete'}
        {...confirmButtonProps}
      >
        <Delete />
      </ConfirmButton>
    </TableCell>
  );
};

export default DeleteCell;
