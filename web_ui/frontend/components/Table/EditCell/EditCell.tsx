import { IconButton, TableCell } from '@mui/material';
import { Edit } from '@mui/icons-material';

interface EditCellProps {
  href: string;
}

const EditCell = ({ href }: EditCellProps) => {
  return (
    <TableCell>
      <IconButton href={href} aria-label={'Edit'}>
        <Edit />
      </IconButton>
    </TableCell>
  );
};

export default EditCell;
