import { DowntimeClass, DowntimeSeverity } from '@/types';

export { ServerDowntimePage } from './Server';
export { DirectorDowntimePage } from './Director';
export { RegistryDowntimePage } from './Registry';

// Used to key useSWR to keep things updated across posts
export const ServerDowntimeKey = 'ServerDowntime';

export const DowntimeSeverities: DowntimeSeverity[] = [
  'Outage (completely inaccessible)',
  'Severe (most services down)',
  'Intermittent Outage (may be up for some of the time)',
  "No Significant Outage Expected (you shouldn't notice)",
];

export const DowntimeClasses: DowntimeClass[] = ['SCHEDULED', 'UNSCHEDULED'];
