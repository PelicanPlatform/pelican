import { InfoOutlined, WarningAmber } from '@mui/icons-material';
import { SvgIconProps } from '@mui/material';

import { DowntimeSeverity } from '@/types';

interface DowntimeIconProps extends Omit<SvgIconProps, 'color'> {
  severity: DowntimeSeverity;
}

const DowntimeIcon = ({ severity, ...props }: DowntimeIconProps) => {
  switch (severity) {
    case 'Outage (completely inaccessible)':
      return <WarningAmber color={'error'} {...props} />;
    case 'Severe (most services down)':
      return <WarningAmber color={'error'} {...props} />;
    case 'Intermittent Outage (may be up for some of the time)':
      return <WarningAmber color={'warning'} {...props} />;
    case "No Significant Outage Expected (you shouldn't notice)":
      return <InfoOutlined color={'info'} {...props} />;
  }
};

export default DowntimeIcon;
