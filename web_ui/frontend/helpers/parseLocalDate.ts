/**
 * Parses the `YYYY-MM-DD` value of an `<input type='date'>` as midnight in the
 * browser's local timezone.
 *
 * `new Date('YYYY-MM-DD')` must not be used for this: the ECMAScript spec parses
 * date-only ISO strings as UTC, so west of Greenwich the result lands on the
 * previous local day (e.g. picking Oct 31 yields Oct 30, 7 PM in US Central).
 * @param value - The date input's value, e.g. '2026-10-31'
 * @returns The local-midnight Date, or undefined if the value is not a valid date
 */
function parseLocalDate(value: string): Date | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (match === null) {
    return undefined;
  }
  const [year, month, day] = match.slice(1).map(Number);
  const date = new Date(year, month - 1, day);
  // Reject values like 2026-02-30 that Date would silently roll over
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day
  ) {
    return undefined;
  }
  return date;
}

export default parseLocalDate;


export type Filter<V> {
  operation: "lt" | "eq"
  value: V
}

Filter
