import { Box, Grid, Paper, Typography } from '@mui/material';
import { green, grey, blue } from '@mui/material/colors';

import {
  ProjectTable,
  TransferRateGraph,
} from '@/app/origin/metrics/components';
import { CPUGraph } from '@/app/origin/metrics/components/CPUGraph';
import { MemoryGraph } from '@/app/origin/metrics/components/MemoryGraph';
import {
  BigBytesMetric,
  BigMetric,
  BigNumber,
} from '@/app/origin/metrics/components/BigNumber';
import { StorageGraph } from '@/app/origin/metrics/components/StorageGraph';

const Page = () => {
  return (
    <Grid container spacing={1} direction={'row'}>
      <Grid item xs={4} display={'flex'}>
        <Grid
          container
          spacing={1}
          justifyContent={'space-between'}
          flexGrow={1}
        >
          {[
            <ProjectTable key={'project-table'} />,
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
            <StorageGraph key={'storage-graph'} />,
          ].map((component, index) => (
            <Grid key={index} item xs={12} display={'flex'} height={'21vh'}>
              <Paper sx={{ width: '100%' }}>{component}</Paper>
            </Grid>
          ))}
        </Grid>
      </Grid>
      <Grid item xs={8}>
        <Grid
          container
          spacing={1}
          justifyContent={'space-between'}
          flexGrow={1}
        >
          <Grid item xs={12} display={'flex'} height={'28vh'}>
            <Paper sx={{ flexGrow: 1 }}>
              <TransferRateGraph />
            </Paper>
          </Grid>
          <Grid item xs={12} display={'flex'} height={'28vh'}>
            <Paper sx={{ flexGrow: 1 }}>
              <CPUGraph />
            </Paper>
          </Grid>
          <Grid item xs={12} display={'flex'} height={'28vh'}>
            <Paper sx={{ flexGrow: 1 }}>
              <MemoryGraph />
            </Paper>
          </Grid>
        </Grid>
      </Grid>
      <Grid item xs={12}>
        <Paper>
          <Box p={1} bgcolor={grey[200]} borderRadius={1}>
            <Grid container>
              <Grid item xs={6}>
                <Grid container>
                  <Grid item xs={4}>
                    <BigMetric
                      title={'Pelican Threads'}
                      finalType={'last'}
                      metric={'go_threads'}
                      color={green[300]}
                    />
                  </Grid>
                  <Grid item xs={4}>
                    <BigMetric
                      title={'XRootD Running Threads'}
                      finalType={'last'}
                      metric={'xrootd_sched_thread_count{state="running"}'}
                      color={blue[200]}
                    />
                  </Grid>
                  <Grid item xs={4}>
                    <BigMetric
                      title={'XRootD Idle Threads'}
                      metric={'xrootd_sched_thread_count{state="idle"}'}
                      finalType={'last'}
                      color={grey[400]}
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Grid item xs={6}>
                <Grid container>
                  <Grid item xs={4}>
                    <BigBytesMetric
                      metric={'xrootd_transfer_bytes{type="read"}'}
                      title={'Bytes `read`'}
                      finalType={'sum'}
                      color={green[300]}
                    />
                  </Grid>
                  <Grid item xs={4}>
                    <BigBytesMetric
                      metric={'xrootd_transfer_bytes{type="readv"}'}
                      title={'Bytes `readv'}
                      finalType={'sum'}
                      color={green[300]}
                    />
                  </Grid>
                  <Grid item xs={4}>
                    <BigBytesMetric
                      metric={'xrootd_transfer_bytes{type="write"}'}
                      title={'Bytes `write`'}
                      finalType={'sum'}
                      color={green[300]}
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Grid item xs={6}>
                <BigMetric
                  title={'Go Routines'}
                  finalType={'last'}
                  metric={'go_goroutines'}
                  color={green[300]}
                />
              </Grid>
              <Grid item xs={6}>
                <BigMetric
                  title={'XRootD Server Connections'}
                  metric={'xrootd_server_connection_count'}
                  finalType={'last'}
                  color={green[300]}
                />
              </Grid>
            </Grid>
          </Box>
        </Paper>
      </Grid>
    </Grid>
  );
};

export default Page;
