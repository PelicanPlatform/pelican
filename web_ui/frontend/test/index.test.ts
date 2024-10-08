import { getSmallestByteCategory, toBytes } from '@/helpers/bytes';
import { replaceQueryParameters, TimeDuration } from '@/components';

describe('Testing Helpers', () => {
  test('toBytes', () => {
    // Basic
    expect(toBytes(1000)).toEqual({ value: 1, label: 'KB' });

    // Unit Conversions
    expect(toBytes(1000, 'KB')).toEqual({ value: 1, label: 'KB' });
    expect(toBytes(1000, 'MB')).toEqual({ value: 0.001, label: 'MB' });
    expect(toBytes(1000, 'GB')).toEqual({ value: 0.000001, label: 'GB' });
    expect(toBytes(1000, 'TB')).toEqual({ value: 0.000000001, label: 'TB' });
    expect(toBytes(1000, 'PB')).toEqual({ value: 0.000000000001, label: 'PB' });
    expect(toBytes(1000, 'EB')).toEqual({
      value: 0.000000000000001,
      label: 'EB',
    });
    expect(toBytes(1000, 'ZB')).toEqual({
      value: 0.000000000000000001,
      label: 'ZB',
    });

    // Large Numbers
    expect(toBytes(361052659)).toEqual({ value: 361.052659, label: 'MB' });
    expect(toBytes(10 ** 9)).toEqual({ value: 1, label: 'GB' });
  });

  test('getSmallestByteCategory', () => {
    expect(getSmallestByteCategory([1000, 1000, 1000])).toEqual('KB');
    expect(getSmallestByteCategory([1000, 1000, 1000, 1000])).toEqual('KB');
    expect(getSmallestByteCategory([10 ** 9, 10 ** 6])).toEqual('MB');
    expect(getSmallestByteCategory([10 ** 9, 10 ** 3])).toEqual('KB');
    expect(getSmallestByteCategory([10 ** 9, 10 ** 1])).toEqual('B');

    // Reverse the order
    expect(getSmallestByteCategory([10 ** 1, 10 ** 9])).toEqual('B');
  });

  test('replaceQueryParameters', () => {
    expect(replaceQueryParameters('Hello, World!', {})).toEqual(
      'Hello, World!'
    );
    expect(
      replaceQueryParameters('Hello, ${range}!', {
        range: TimeDuration.fromString('1d'),
      })
    ).toEqual('Hello, 1d!');
    expect(
      replaceQueryParameters('Hello, ${range}${range}!', {
        range: TimeDuration.fromString('1d'),
      })
    ).toEqual('Hello, 1d1d!');
    expect(
      replaceQueryParameters('Hello, ${range}${rate}${resolution}!', {
        range: TimeDuration.fromString('1d'),
      })
    ).toEqual('Hello, 1d${rate}${resolution}!');
    expect(
      replaceQueryParameters('Hello, ${range}${rate}${resolution}!', {
        range: TimeDuration.fromString('1d'),
        rate: TimeDuration.fromString('1m'),
        resolution: TimeDuration.fromString('1y'),
      })
    ).toEqual('Hello, 1d1m1y!');
  });
});
