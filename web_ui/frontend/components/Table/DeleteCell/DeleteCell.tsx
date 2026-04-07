import ConfirmButton from '@chtc/web-components/ConfirmButton';
import { TableCell } from '@mui/material';
import { Delete } from '@mui/icons-material';

interface DeleteCellProps {
  handleDelete: () => void;
}

const DeleteCell = ({ handleDelete }: DeleteCellProps) => {
  return (
    <TableCell>
      <ConfirmButton
        color={'error'}
        onConfirm={handleDelete}
        aria-label={'Delete'}
      >
        <Delete />
      </ConfirmButton>
    </TableCell>
  );
};

export default DeleteCell;
