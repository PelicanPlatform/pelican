import ConfirmButton from "@chtc/web-components/ConfirmButton";
import {TableCell} from "@mui/material";
import {Delete} from "@mui/icons-material";

import { UserService, User, fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { useContext } from 'react';
import {AlertDispatchContext} from "@/components/AlertProvider";
import {CellComponentProps} from "@/components/Table";

const makeDeleteUserCell = (mutate: () => void) => {

  const DeleteUserCell = ({row: user}: CellComponentProps<User, any>) => {

    const dispatch = useContext(AlertDispatchContext);

    const handleDelete = async () => {
      await alertOnError(
        () => UserService.delete(user.id),
        `Error Deleting User: ${user.username}`,
        dispatch
      );
      mutate();
    }

    return (
      <TableCell>
        <ConfirmButton
          color={"error"}
          onConfirm={handleDelete}
        >
          <Delete />
        </ConfirmButton>
      </TableCell>
    )
  }

  DeleteUserCell.displayName = "DeleteUserCell";

  return DeleteUserCell;
}


export default makeDeleteUserCell;
