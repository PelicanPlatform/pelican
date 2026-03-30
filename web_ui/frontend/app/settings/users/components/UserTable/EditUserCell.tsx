import ConfirmButton from "@chtc/web-components/ConfirmButton";
import { IconButton, TableCell } from '@mui/material';
import { Delete, Edit } from '@mui/icons-material';

import { UserService, User, fetchApi } from '@/helpers/api';
import { alertOnError } from '@/helpers/util';
import { useContext } from 'react';
import {AlertDispatchContext} from "@/components/AlertProvider";
import {CellComponentProps} from "@/components/Table";

const EditUserCell = ({row: user}: CellComponentProps<User, any>) => {

  return (
    <TableCell>
      <IconButton href={`./edit?id=${user.id}`}>
        <Edit />
      </IconButton>
    </TableCell>
  )
}



export default EditUserCell;
