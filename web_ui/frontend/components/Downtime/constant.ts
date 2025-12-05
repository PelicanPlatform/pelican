import { DateTime } from 'luxon';
import { DowntimeClass, DowntimeSeverity } from '@/types';

export const defaultDowntime = {
  serverId: '',
  serverName: '',
  startTime: DateTime.now().toMillis(),
  endTime: DateTime.now().plus({ days: 1 }).toMillis(),
  description: '',
  severity: 'Outage (completely inaccessible)' as DowntimeSeverity,
  class: 'SCHEDULED' as DowntimeClass,
};
