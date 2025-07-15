/**
 * Returns an array of Date objects representing all the days in the month of the given date.
 * @param compDate - The date from which to derive the month
 */
function getDaysInMonth(compDate: Date): Date[] {
  const days: Date[] = [];
  // month is 0-indexed (0 = January, 11 = December)
  const month = compDate.getMonth();
  const date = new Date(compDate.getFullYear(), compDate.getMonth(), 1);
  while (date.getMonth() === month) {
    days.push(new Date(date));
    date.setDate(date.getDate() + 1);
  }
  return days;
}

export default getDaysInMonth;
