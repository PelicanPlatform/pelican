import { Grid, Paper } from '@mui/material';
import { green } from '@mui/material/colors';

import { BigBytesMetric, ProjectTable } from '@/components/metrics';

import {
  BytesMetricBoxPlot,
  MetricBoxPlot,
} from '@/app/director/metrics/components/MetricBoxPlot';
import { StorageTable } from '@/app/director/metrics/components/StorageTable';
import { TransferBarGraph } from '@/app/director/metrics/components/TransferBarGraph';
import ServerUptime from '@/app/director/metrics/components/ServerUptime';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

const Page = () => {
  return (
    <AuthenticatedContent
      allowedRoles={['admin']}
      trustThenValidate={true}
      redirect={true}
    >
      <Grid container spacing={1} direction={'row'}>
        <Grid
          display={'flex'}
          size={{
            xs: 12,
            md: 5
          }}>
          <Grid container spacing={1}>
            {[
              <ServerUptime key={'server-count-var-graph'} />,
              <StorageTable key={'storage-table'} />,
              <ProjectTable key={'project-table'} />,
            ].map((component, index) => (
              <Grid key={index} display={'flex'} height={'45vh'} size={12}>
                <Paper sx={{ width: '100%' }}>{component}</Paper>
              </Grid>
            ))}
          </Grid>
        </Grid>
        <Grid
          display={'flex'}
          size={{
            xs: 12,
            md: 7
          }}>
          <Grid container spacing={1} flexGrow={1}>
            <Grid display={'flex'} size={12}>
              <Grid container spacing={1}>
                {[
                  <MetricBoxPlot
                    key={'transfer-bytes'}
                    metric={`sum by (server_name) (increase(xrootd_transfer_bytes[$\{range}]))`}
                    title={'XRootD Transfer Bytes'}
                  />,
                  <MetricBoxPlot
                    key={'transfer-operations'}
                    metric={`sum by (server_name) (increase(xrootd_transfer_operations_count[$\{range}]))`}
                    title={'XRootD Transfer Operations'}
                  />,
                  <BytesMetricBoxPlot
                    key={'bytes'}
                    metric={'go_memstats_alloc_bytes'}
                    title={'Server Memory Usage'}
                  />,
                  <MetricBoxPlot
                    key={'cpu'}
                    metric={
                      'avg by (server_name) (irate(process_cpu_seconds_total[${range}]))'
                    }
                    title={'CPU Usage by Core'}
                  />,
                  <MetricBoxPlot
                    key={'threads'}
                    metric={
                      'sum by (server_name) (sum_over_time(xrootd_server_connection_count[${range}])) / sum by (server_name) (count_over_time(xrootd_server_connection_count[${range}]))'
                    }
                    title={'XRootD Server Connections'}
                  />,
                  <MetricBoxPlot
                    key={'scheduler'}
                    metric={
                      'sum by (server_name) (sum_over_time(xrootd_sched_thread_count[${range}])) / sum by (server_name) (count_over_time(xrootd_sched_thread_count[${range}]))'
                    }
                    title={'XRootD Scheduler Threads'}
                  />,
                ].map((component, index) => (
                  <Grid
                    key={index}
                    display={'flex'}
                    maxHeight={'50%'}
                    minHeight={'20rem'}
                    size={{
                      xs: 12,
                      sm: 6
                    }}>
                    <Paper sx={{ width: '100%' }}>{component}</Paper>
                  </Grid>
                ))}
              </Grid>
            </Grid>
          </Grid>
        </Grid>
        <Grid size={12}>
          <Grid container minHeight={'20rem'}>
            <Grid
              display={'flex'}
              size={{
                xs: 12,
                md: 6
              }}>
              <Paper sx={{ width: '100%', minHeight: '20rem' }}>
                <TransferBarGraph />
              </Paper>
            </Grid>
            <Grid
              display={'flex'}
              size={{
                xs: 12,
                md: 6
              }}>
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
                  <Grid
                    key={index}
                    display={'flex'}
                    size={{
                      xs: 12,
                      md: 6
                    }}>
                    <Paper sx={{ width: '100%' }}>{component}</Paper>
                  </Grid>
                ))}
              </Grid>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </AuthenticatedContent>
  );
};

export default Page;
