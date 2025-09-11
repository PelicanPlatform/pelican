import { DowntimeGet } from '@/types';

import { DateTime } from 'luxon';
import isRecent from '@/components/Downtime/isRecent';

const sortDowntimes = (downtimes: DowntimeGet[]) => {
  return downtimes.sort((a, b) => {
    return scoreDowntime(b) - scoreDowntime(a);
  });
};

/**
 * Score function to determine order
 * Goal is to group by recently updated, then start time
 * @param downtime
 */
const scoreDowntime = (downtime: DowntimeGet): number => {
  const recentlyUpdated = isRecent(DateTime.fromMillis(downtime.updatedAt));
  const score = recentlyUpdated ? 100000000000000 : 0;
  return score + downtime.startTime;
};

export default sortDowntimes;
