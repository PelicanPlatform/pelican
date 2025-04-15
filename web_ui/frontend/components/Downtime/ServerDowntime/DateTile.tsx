import { TileArgs, TileContentFunc } from 'react-calendar';
import { DowntimeGet, DowntimeSeverity } from '@/types';
import { Box, Divider, Tooltip } from '@mui/material';

interface DateTileProps extends TileArgs {
  downtimes?: DowntimeGet[];
}

const DateTile = ({
  downtimes,
  activeStartDate,
  date,
  view,
}: DateTileProps) => {
  // Pull out the downtimes that are applicable to the date
  const applicableDowntimes = downtimes?.filter((downtime) => {
    const start = new Date(downtime.startTime);
    const end = new Date(downtime.endTime);
    return date >= start && (date <= end || downtime.endTime === -1);
  });

  const severitiesBinned = binBySeverity(applicableDowntimes || []);

  return (
    <Box
      sx={{
        flexGrow: 1,
        maxHeight: '50%',
        display: 'flex',
      }}
    >
      {Object.entries(severitiesBinned).map(([severity, count], index) => {
        return (
          <Tooltip title={severity} key={index}>
            <Box
              sx={{
                backgroundColor: getSeverityColor(severity as DowntimeSeverity),
                flexGrow: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {count}
            </Box>
          </Tooltip>
        );
      })}
    </Box>
  );
};

const binBySeverity = (downtimes: DowntimeGet[]) => {
  let binnedSeverities = {
    'Outage (completely inaccessible)': 0,
    'Severe (most services down)': 0,
    'Intermittent Outage (may be up for some of the time)': 0,
    "No Significant Outage Expected (you shouldn't notice)": 0,
  } as Record<DowntimeSeverity, number>;

  // Loop through the downtimes and bin them by severity
  downtimes.forEach((d) => (binnedSeverities[d.severity] += 1));

  // Filter out the severities that are 0
  Object.keys(binnedSeverities).forEach((key) => {
    if (binnedSeverities[key as DowntimeSeverity] === 0) {
      delete binnedSeverities[key as DowntimeSeverity];
    }
  });

  return binnedSeverities;
};

const getMaxSeverityDowntime = (downtimes: DowntimeGet[]) => {
  return downtimes.reduce((prev, curr) => {
    switch (curr.severity) {
      case 'Outage (completely inaccessible)':
        return Math.max(prev, 4);
      case 'Severe (most services down)':
        return Math.max(prev, 3);
      case 'Intermittent Outage (may be up for some of the time)':
        return Math.max(prev, 2);
      case "No Significant Outage Expected (you shouldn't notice)":
        return Math.max(prev, 1);
      default:
        return prev;
    }
  }, 0);
};

const getSeverityColor = (severity: DowntimeSeverity) => {
  switch (severity) {
    case 'Outage (completely inaccessible)':
      return 'error.light';
    case 'Severe (most services down)':
      return 'warning.light';
    case 'Intermittent Outage (may be up for some of the time)':
      return 'warning.light';
    case "No Significant Outage Expected (you shouldn't notice)":
      return 'info.light';
    default:
      return 'inherit';
  }
};

export default DateTile;
