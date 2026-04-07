import { IconButton, TableCell } from '@mui/material';
import { Visibility } from '@mui/icons-material';

interface ViewCellProps {
  href: string;
}

const ViewCell = ({ href }: ViewCellProps) => {
  return (
    <TableCell>
      <IconButton href={href} aria-label={'View'}>
        <Visibility />
      </IconButton>
    </TableCell>
  );
};

export default ViewCell;
