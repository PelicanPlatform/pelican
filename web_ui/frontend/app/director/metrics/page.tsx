import { Grid, Paper } from '@mui/material';
import { green } from '@mui/material/colors';

import { ProjectTable } from '@/app/origin/metrics/components';
import { BigBytesMetric } from '@/app/origin/metrics/components/BigNumber';
import {
  BytesMetricBoxPlot,
  MetricBoxPlot,
} from '@/app/director/metrics/components/MetricBoxPlot';
import { StorageTable } from '@/app/director/metrics/components/StorageTable';
import { TransferBarGraph } from '@/app/director/metrics/components/TransferBarGraph';

const Page = () => {
  return (
    <Grid container spacing={1} direction={'row'}>
      <Grid item xs={12} md={5} display={'flex'}>
        <Grid container spacing={1}>
          {[
            <ProjectTable key={'project-table'} />,
            <StorageTable key={'storage-table'} />,
          ].map((component, index) => (
            <Grid key={index} item xs={12} display={'flex'} height={'45vh'}>
              <Paper sx={{ width: '100%' }}>{component}</Paper>
            </Grid>
          ))}
        </Grid>
      </Grid>
      <Grid item xs={12} md={7} display={"flex"}>
        <Grid container spacing={1} flexGrow={1}>
          <Grid item xs={12} display={'flex'}>
            <Grid container spacing={1}>
              {[
                <BytesMetricBoxPlot metric={'go_memstats_alloc_bytes'} title={'Server Memory Usage'} />,
                <MetricBoxPlot
                  metric={
                    'avg by (server_name) (irate(process_cpu_seconds_total[${range}]))'
                  }
                  title={'CPU Usage by Core'}
                />,
                <MetricBoxPlot
                  metric={
                    'sum by (server_name) (sum_over_time(xrootd_server_connection_count[${range}])) / sum by (server_name) (count_over_time(xrootd_server_connection_count[${range}]))'
                  }
                  title={'XRootD Server Connections'}
                />,
                <MetricBoxPlot
                  metric={
                    'sum by (server_name) (sum_over_time(xrootd_sched_thread_count[${range}])) / sum by (server_name) (count_over_time(xrootd_sched_thread_count[${range}]))'
                  }
                  title={'XRootD Scheduler Threads'}
                />
              ].map((component, index) => (
                <Grid key={index} item xs={12} sm={6} display={'flex'} maxHeight={"50%"} minHeight={"20rem"}>
                  <Paper sx={{ width: '100%' }}>{component}</Paper>
                </Grid>
              ))}
            </Grid>
          </Grid>
        </Grid>
      </Grid>
      <Grid item xs={12}>
        <Grid container minHeight={"20rem"}>
          <Grid item xs={12} md={6} display={'flex'}>
            <Paper sx={{ width: '100%', minHeight: '20rem' }}>
              <TransferBarGraph />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6} display={'flex'}>
            <Grid container>
              {[
                <BigBytesMetric
                  key={'rx'}
                  metric={'xrootd_server_bytes{direction="rx"}'}
                  title={'Bytes Received'}
                  color={green[300]}
                />,
                <BigBytesMetric
                  key={'tx'}
                  metric={'xrootd_server_bytes{direction="tx"}'}
                  title={'Bytes Transferred'}
                  color={green[300]}
                />,
              ].map((component, index) => (
                <Grid key={index} item xs={12} md={6} display={'flex'}>
                  <Paper sx={{ width: '100%' }}>{component}</Paper>
                </Grid>
              ))}
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Grid>
  );
};

export default Page;
