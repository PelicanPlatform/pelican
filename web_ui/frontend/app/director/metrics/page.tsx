import { Box, Grid, Paper, Typography } from '@mui/material';
import { green, grey, blue } from '@mui/material/colors';

import { ProjectTable, TransferRateGraph } from '@/app/origin/metrics/components';
import { CPUGraph } from '@/app/origin/metrics/components/CPUGraph';
import { MemoryGraph } from '@/app/origin/metrics/components/MemoryGraph';
import { BigBytesMetric, BigMetric, BigNumber } from '@/app/origin/metrics/components/BigNumber';
import { StorageGraph } from '@/app/origin/metrics/components/StorageGraph';
import { BytesTransferred } from '@/app/director/metrics/components/BytesTransferred';
import { BytesMetricBoxPlot, MetricBoxPlot } from '@/app/director/metrics/components/MetricBoxPlot';
import { CPUBoxPlot } from '@/app/director/metrics/components/CPUBoxPlot';
import { StorageTable } from '@/app/director/metrics/components/StorageTable';
import { TransferBarGraph } from '@/app/director/metrics/components/TransferBarGraph';

const Page = () => {
  return (
    <Grid container spacing={1} direction={"row"}>
      <Grid item xs={5} display={"flex"}>
        <Grid container spacing={1}>
          {
            [
              <ProjectTable />,
              <StorageTable/>
            ].map((component, index) => (
              <Grid key={index} item xs={12} display={"flex"} height={"45vh"}>
                <Paper sx={{width: "100%"}}>
                  {component}
                </Paper>
              </Grid>
            ))
          }
        </Grid>
      </Grid>
      <Grid item xs={7}>
        <Grid container spacing={1} flexGrow={1}>
          <Grid item xs={12} display={"flex"} height={"35vh"}>
            <Grid container spacing={1}>
              <Grid item xs={4}>
                <Paper sx={{flexGrow: 1, height: "100%"}}>
                  <BytesMetricBoxPlot metric={"go_memstats_alloc_bytes"} title={"Server Memory Usage"}/>
                </Paper>
              </Grid>
              <Grid item xs={4}>
                <Paper sx={{flexGrow: 1, height: "100%"}}>
                  <CPUBoxPlot/>
                </Paper>
              </Grid>
              <Grid item xs={4}>
                <Paper sx={{flexGrow: 1, height: "100%"}}>
                  <MetricBoxPlot metric={"xrootd_server_connection_count"} title={"XRootD Server Connections"}/>
                </Paper>
              </Grid>
            </Grid>
          </Grid>
          <Grid item xs={12} display={"flex"} height={"32vh"}>
            <Paper sx={{flexGrow: 1}}>
              <TransferBarGraph/>
            </Paper>
          </Grid>
          <Grid item xs={12} display={"flex"} height={"23vh"}>
            <Grid container>
              {
                [
                  <BigBytesMetric metric={"xrootd_server_bytes{direction=\"rx\"}"} title={"Bytes Received"} color={green[300]} />,
                  <BigBytesMetric metric={"xrootd_server_bytes{direction=\"tx\"}"} title={"Bytes Transferred"} color={green[300]} />,
                ].map((component, index) => (
                  <Grid key={index} item xs={6} display={"flex"}>
                    <Paper sx={{flexGrow: 1}}>
                      {component}
                    </Paper>
                  </Grid>
                ))
              }
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Grid>
  );
}

export default Page;
