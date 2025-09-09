import {
  Box,
  Collapse,
  Divider,
  Grid,
  IconButton,
  Paper,
  Tooltip,
  Typography,
} from '@mui/material';
import React, { useContext, useState } from 'react';
import { DateTime } from 'luxon'
import DowntimeIcon from './DowntimeIcon';
import { Edit } from '@mui/icons-material';
import { DowntimeEditDispatchContext } from '@/components/Downtime/DowntimeEditContext';
import { DowntimeGet } from '@/types';
import extendPrefix from '@/helpers/extendPrefix';
import isRecent from '@/components/Downtime/isRecent';

interface GeneralDowntimeCardProps {
  downtime: DowntimeGet;
  federationLevel?: boolean;
  editable?: boolean;
}

/**
 *
 * @param downtime
 * @param federationLevel - If this component is intended for use in an aggregate of a federations downtimes
 * @param editable
 * @constructor
 */
const DowntimeCard = ({
  downtime,
  federationLevel = false,
  editable = false,
}: GeneralDowntimeCardProps) => {
  const setDowntime = useContext(DowntimeEditDispatchContext);

  const [hovered, setHovered] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const {type, adjustedPrefix} = extendPrefix(downtime.serverName)

  const updatedRecently = isRecent(DateTime.fromMillis(downtime.updatedAt));

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
          borderRadius: 2
        }}
      >
        <Box width={'100%'} sx={{bgcolor: updatedRecently ? '#fff4e5' : 'inherit'}} p={1}>
          <Grid container>
            <Grid size={12}>
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
                  {federationLevel && (
                    <Typography variant={'subtitle2'}>
                      {adjustedPrefix || downtime.serverName}
                    </Typography>
                  )}
                  <Typography variant={'subtitle2'}>
                    {downtime.description}
                  </Typography>
                </Box>
                {editable && (
                  <Box>
                    <IconButton
                      onClick={() => {
                        setDowntime(downtime);
                      }}
                    >
                      <Edit />
                    </IconButton>
                  </Box>
                )}
              </Box>
            </Grid>
            <Grid size={12}>
              <Divider></Divider>
            </Grid>
            <Grid size={12}>
              <Box width={'100%'} borderRadius={2} mt={1}>
                <Grid container>
                  <Grid size={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Severity:</b> {downtime.severity}
                    </Typography>
                  </Grid>
                  <Grid size={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Local Start Time:</b>{' '}
                      {new Date(downtime.startTime).toLocaleString()}
                    </Typography>
                  </Grid>
                  <Grid size={6}>
                    <Typography variant={'subtitle2'}>
                      <b>Class:</b> {downtime.class}
                    </Typography>
                  </Grid>
                  <Grid size={6}>
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
                    <Grid size={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Created By:</b> {downtime.createdBy}
                      </Typography>
                    </Grid>
                    <Grid size={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Local Creation Time:</b>{' '}
                        {new Date(downtime.createdAt).toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid size={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Updated By:</b> {downtime.updatedBy}
                      </Typography>
                    </Grid>
                    <Grid size={6}>
                      <Typography variant={'subtitle2'}>
                        <b>Local Update Time:</b>{' '}
                        {new Date(downtime.updatedAt).toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid size={6}>
                      <Typography variant={'subtitle2'}>
                        <b>ID:</b> {downtime.id}
                      </Typography>
                    </Grid>
                    {federationLevel && (
                      <Grid size={6}>
                        <Typography variant={'subtitle2'}>
                          <b>Server:</b> {downtime.source}
                        </Typography>
                      </Grid>
                    )}
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

export default DowntimeCard;
