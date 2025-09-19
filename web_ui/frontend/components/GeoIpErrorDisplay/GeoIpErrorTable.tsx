import {
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';

import { GeoIPOverride } from '@/components/configuration';
import { VectorResult } from '@/components';

import StyledTableCell from './StyledTableCell';

interface GeoIpErrorTableProps {
  ipErrors: VectorResult[] | undefined;
  setIp: (ip: string) => void;
  setOpenForm: (open: boolean) => void;
  geoIpOverrides: Record<string, GeoIPOverride>;
}

const GeoIpErrorTable = ({ipErrors, setIp, setOpenForm, geoIpOverrides}: GeoIpErrorTableProps) => {

  return (
    <TableContainer sx={{ maxHeight: 250 }}>
      <Table
        stickyHeader
        sx={{ minWidth: 650 }}
        size={'small'}
        aria-label='simple table'
      >
        <TableHead>
          <TableRow>
            <StyledTableCell>Un-located Network</StyledTableCell>
            <StyledTableCell align='right'>Name</StyledTableCell>
            <StyledTableCell align={'right'}># of Errors</StyledTableCell>
            <StyledTableCell align='right'>Locate</StyledTableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {ipErrors &&
            ipErrors
              .map((row) => (
                <TableRow
                  key={row.metric?.network}
                  sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                >
                  <TableCell>{row.metric?.network}</TableCell>
                  <TableCell align='right'>{row.metric?.name}</TableCell>
                  <TableCell align='right'>
                    {parseInt(row.value[1]).toLocaleString()}
                  </TableCell>
                  <TableCell align='right'>
                    <Button
                      onClick={() => {
                        setIp(row.metric?.network);
                        setOpenForm(true);
                      }}
                    >
                      {Object.keys(geoIpOverrides).includes(
                        row.metric?.network
                      )
                        ? 'Pending'
                        : 'Locate'}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
          }
          {!ipErrors && (
            <TableRow>
              <TableCell colSpan={4} align='center'>
                No un-located networks found.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

export default GeoIpErrorTable;
