import ConfirmButton from '@chtc/web-components/ConfirmButton';
import { TableCell } from '@mui/material';
import { Delete } from '@mui/icons-material';

import { UserService, User, fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { useContext } from 'react';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { CellComponentProps } from '@/components/Table';

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
