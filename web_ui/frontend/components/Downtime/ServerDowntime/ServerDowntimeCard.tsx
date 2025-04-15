import { DowntimeGet } from '@/types';
import {
  Box,
  Collapse,
  Divider,
  Grid,
  Grow,
  IconButton,
  Paper,
  Slide,
  Tooltip,
  Typography,
} from '@mui/material';
import React, { useContext, useState } from 'react';
import DowntimeIcon from '@/components/Downtime/ServerDowntime/DowntimeIcon';
import { Edit } from '@mui/icons-material';
import { DowntimeEditDispatchContext } from '@/components/Downtime/DowntimeEditContext';

export interface ServerDowntimeCardProps {
  downtime: DowntimeGet;
}

const ServerDowntimeCard = ({ downtime }: ServerDowntimeCardProps) => {
  const setDowntime = useContext(DowntimeEditDispatchContext);

  const [hovered, setHovered] = useState(false);
  const [expanded, setExpanded] = useState(false);

  return (
    <Box
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={() => setExpanded(!expanded)}
    >
      <Paper
        elevation={hovered ? 3 : 1}
        sx={{
          width: '100%',
          cursor: 'pointer',
          display: 'flex',
          flexDirection: 'row',
          justifyContent: 'space-between',
          border: 'solid #ececec 1px',
          borderRadius: 2,
          p: 1,
        }}
      >
        <Box width={'100%'}>
          <Grid container>
            <Grid item xs={12}>
              <Box display={'flex'} flexDirection={'row'} alignItems={'center'}>
                <Box pr={1}>
                  <Tooltip title={downtime.severity}>
                    <DowntimeIcon
                      sx={{ height: '100%' }}
                      fontSize={'large'}
                      severity={downtime.severity}
                    />
                  </Tooltip>
                </Box>
                <Box flexGrow={1}>
                  <Typography variant={'subtitle2'}>
                    {downtime.description}
                  </Typography>
                </Box>
                <Box>
                  <IconButton
                    onClick={() => {
                      setDowntime(downtime);
                    }}
                  >
                    <Edit />
                  </IconButton>
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12}>
              <Divider></Divider>
            </Grid>
            <Grid item xs={12}>
              <Box width={'100%'} borderRadius={2} mt={1}>
                <Grid container>
                  <Grid item xs={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Severity:</b> {downtime.severity}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Local Start Time:</b>{' '}
                      {new Date(downtime.startTime).toLocaleString()}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Class:</b> {downtime.class}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Local End Time:</b>{' '}
                      {downtime.endTime === -1
                        ? 'None'
                        : new Date(downtime.endTime).toLocaleString()}
                    </Typography>
                  </Grid>
                </Grid>
                <Collapse in={expanded} timeout={100} sx={{ width: '100%' }}>
                  <Grid container>
                    <Grid item xs={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Created By:</b> {downtime.createdBy}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Local Creation Time:</b>{' '}
                        {new Date(downtime.createdAt).toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant={'subtitle2'}>
                        <b>ID:</b> {downtime.id}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Local Update Time:</b>{' '}
                        {new Date(downtime.updatedAt).toLocaleString()}
                      </Typography>
                    </Grid>
                  </Grid>
                </Collapse>
              </Box>
            </Grid>
          </Grid>
        </Box>
      </Paper>
    </Box>
  );
};

export default ServerDowntimeCard;
