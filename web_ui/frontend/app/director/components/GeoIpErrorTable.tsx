/**
 * Table printing out the errors that occurred during the GeoIP lookup.
 */

import { styled } from '@mui/material/styles';
import {
  Paper,
  Table,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableBody,
  Button,
  Modal,
  Typography,
} from '@mui/material';
import { tableCellClasses } from '@mui/material/TableCell';
import useSWR from 'swr';

import { query_raw, VectorResponseData } from '@/components';
import { GeoIPOverride, GeoIPOverrideForm, ParameterValueRecord, submitConfigChange } from '@/components/configuration';
import { alertOnError } from '@/helpers/util';
import { Dispatch, useCallback, useContext, useMemo, useState } from 'react';
import { AlertDispatchContext, AlertReducerAction } from '@/components/AlertProvider';
import { getConfig } from '@/helpers/api';
import LatitudeLongitudePicker from '@/components/LatitudeLongitudePicker';
import ObjectModal from '@/components/configuration/Fields/ObjectField/ObjectModal';
import CircularProgress from '@mui/material/CircularProgress';

const GeoIpErrorTable = () => {

  const dispatch = useContext(AlertDispatchContext);
  const {data: ipErrors} = useSWR('geoip_errors', getIpErrorRows)

  const { data: config, mutate, error, isValidating } = useSWR<ParameterValueRecord | undefined>(
    'getConfig',
    async () =>
      await alertOnError(getOverriddenGeoIps, 'Could not get config', dispatch)
  );
  const patchedIps = useMemo(() => {
    return config?.GeoIPOverrides === undefined ?
      [] :
      Object.values(config.GeoIPOverrides).map((x: GeoIPOverride) => x.ip)
  }, [config])
  const [geoIPOverrides, setGeoIPOverrides] = useState<Record<string, GeoIPOverride>>({})

  const [open, setOpen] = useState(false)
  const [ip, setIp] = useState("")

  const onSubmit = useCallback((x: GeoIPOverride) => {
    setGeoIPOverrides((p) => {
      return {...p, [x.ip]: x}
    })
    setOpen(false)
  }, [])

  return (
    <>
      <Typography variant={"h4"} pb={2}>
        Un-located Networks
        {isValidating && <CircularProgress size={"24px"} sx={{ml: 1}}/>}
      </Typography>
      <Paper sx={{overflow: "hidden"}}>
        <TableContainer sx={{ maxHeight: 250}}>
          <Table stickyHeader sx={{ minWidth: 650 }} size={"small"} aria-label="simple table">
            <TableHead>
              <TableRow>
                <StyledTableCell>Un-located Network</StyledTableCell>
                <StyledTableCell align="right">Project</StyledTableCell>
                <StyledTableCell align="right">Source</StyledTableCell>
                <StyledTableCell align={"right"}># of Errors</StyledTableCell>
                <StyledTableCell align="right">Locate</StyledTableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {ipErrors && ipErrors
                .filter((x) => !patchedIps.includes(x.metric?.network))
                .sort((a, b) => parseInt(b.value[1]) - parseInt(a.value[1]))
                .map((row) => (
                <TableRow
                  key={row.metric?.network}
                  sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                >
                  <TableCell>{row.metric?.network}</TableCell>
                  <TableCell align="right">{row.metric?.proj}</TableCell>
                  <TableCell align="right">{row.metric?.source}</TableCell>
                  <TableCell align="right">{parseInt(row.value[1]).toLocaleString()}</TableCell>
                  <TableCell align="right">
                    <Button
                      onClick={() => {
                        setIp(row.metric?.network)
                        setOpen(true)
                      }}
                    >
                      {Object.keys(geoIPOverrides).includes(row.metric?.network) ? "Pending" : "Locate"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        {Object.keys(geoIPOverrides).length > 0 && (
          <Button
            sx={{m:1}}
            variant={"outlined"}
            onClick={async () => {
              const overrides = [...Object.values(config?.GeoIPOverrides || []), ...Object.values(geoIPOverrides)]
              const value = await alertOnError(async () => submitConfigChange({GeoIPOverrides: overrides}), 'Could not submit IP patches', dispatch)
              if(value !== undefined) {
                mutate()
                setGeoIPOverrides({})
              }
            }}
          >
            Submit IP Patches ({Object.keys(geoIPOverrides).length})
          </Button>
        )}
      </Paper>
      <ObjectModal name={"Locate Network IP"} handleClose={() => setOpen(!open)} open={open}>
        <GeoIPOverrideForm value={{ip: ip, coordinate: {lat: "37", long: "20"}}} onSubmit={onSubmit} />
      </ObjectModal>
    </>
  )
}

interface GeoUpdateFormProps {
  open: boolean;
  onClose: () => void;
  ip: string;
}

const StyledTableCell = styled(TableCell)(({ theme }) => ({

  [`&.${tableCellClasses.head}`]: {
    backgroundColor: theme.palette.warning.main
  },
}));

const getIpErrorRows = async () => {
  const response = await query_raw<VectorResponseData>("last_over_time(pelican_director_geoip_errors[1d])")
  return response.data.result
}

const getOverriddenGeoIps = async () => {
  let tries = 0
  while(tries < 2) {
    try {
      const response = await getConfig()
      const config = await response.json()
      return {GeoIPOverrides: config.GeoIPOverrides}
    } catch(e) {
      tries++
      await new Promise(r => setTimeout(r, (10 ** tries) * 500));

    }
  }
}

export default GeoIpErrorTable;
