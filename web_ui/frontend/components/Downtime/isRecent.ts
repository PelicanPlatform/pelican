import { DateTime } from 'luxon';

const isRecent = (date: DateTime) => {
  return date > DateTime.now().minus({ minutes: 10 });
}

export default isRecent;
