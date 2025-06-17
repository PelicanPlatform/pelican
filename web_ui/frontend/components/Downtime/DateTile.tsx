import { TileArgs } from 'react-calendar';
import { DowntimeGet, DowntimeSeverity } from '@/types';
import { Box, Tooltip, alpha } from '@mui/material';
import { red, blue, yellow } from '@mui/material/colors';

interface DateTileProps extends TileArgs {
  maxValue?: number;
  binnedDowntimes?: Partial<Record<DowntimeSeverity, number>>;
}

const DateTile = ({ binnedDowntimes = {}, maxValue = 1 }: DateTileProps) => {
  return (
    <Box
      sx={{
        flexGrow: 1,
        display: 'flex',
      }}
    >
      {Object.entries(binnedDowntimes).map(([severity, count], index) => {
        return (
          <Tooltip title={severity} key={index}>
            <Box
              className={'downtime-bar'}
              sx={{
                backgroundColor: getSeverityColor(severity as DowntimeSeverity),
                flexGrow: 1,
                display: 'flex',
                marginTop: 'auto',
                height: `${(count / maxValue) * 100}%`,
                alignItems: 'end',
                justifyContent: 'center',
                color: '#ffffff00',
              }}
            >
              {count == 0 || count}
            </Box>
          </Tooltip>
        );
      })}
    </Box>
  );
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
      return alpha(red[300], 0.6);
    case 'Severe (most services down)':
      return alpha(yellow[300], 0.6);
    case 'Intermittent Outage (may be up for some of the time)':
      return alpha(yellow[100], 0.6);
    case "No Significant Outage Expected (you shouldn't notice)":
      return alpha(blue[300], 0.6);
    default:
      return 'inherit';
  }
};

export default DateTile;
