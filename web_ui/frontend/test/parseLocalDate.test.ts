import parseLocalDate from '@/helpers/parseLocalDate';

test('parses a date input value as local midnight on the same day', () => {
  const date = parseLocalDate('2026-10-31');
  expect(date).toBeDefined();
  expect(date!.getFullYear()).toBe(2026);
  expect(date!.getMonth()).toBe(9);
  expect(date!.getDate()).toBe(31);
  expect(date!.getHours()).toBe(0);
  expect(date!.getMinutes()).toBe(0);
});

test('rejects malformed and out-of-range values', () => {
  expect(parseLocalDate('')).toBeUndefined();
  expect(parseLocalDate('2026-10-31T00:00')).toBeUndefined();
  expect(parseLocalDate('10/31/2026')).toBeUndefined();
  expect(parseLocalDate('2026-02-30')).toBeUndefined();
  expect(parseLocalDate('2026-13-01')).toBeUndefined();
});
