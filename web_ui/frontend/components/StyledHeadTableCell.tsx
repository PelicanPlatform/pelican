import { styled, TableCell } from '@mui/material';
import { tableCellClasses } from '@mui/material/TableCell';

const StyledTableCell = styled(TableCell)(({ theme }) => ({
  [`&.${tableCellClasses.head}`]: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
  },
  [`&.${tableCellClasses.head}:last-of-type`]: {
    borderRadius: '0 5px 0 0',
  },
  [`&.${tableCellClasses.head}:first-of-type`]: {
    borderRadius: '5px 0 0 0',
  },
  [`&.${tableCellClasses.body}`]: {
    fontSize: 14,
  },
}));

export default StyledTableCell;
