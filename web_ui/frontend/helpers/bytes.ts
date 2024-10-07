import { TypeFunction, TypeOrTypeFunction } from '@/helpers/util';

export type ByteType = 'B' | 'KB' | 'MB' | 'GB' | 'TB' | 'PB' | 'EB' | 'ZB' | 'YB';

export type ByteValue = { value: number, label: ByteType }

// List out the Byte increments, each increment being x1000 more bytes than the last
const BYTE_TYPES = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] as ByteType[];

/**
 * Converts bytes its largest possible unit and returns a digit with string label
 */
export const convertToBiggestBytes = (bytes: number): ByteValue => {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] as ByteType[];
  let unitIndex = 0;
  let value = bytes;

  while (value >= 1000 && unitIndex < units.length) {
    value /= 1000;
    unitIndex++;
  }

  return { value, label: units[unitIndex] };
}

export const toBytes = (value: number, unit: ByteType | undefined = undefined): ByteValue => {

  // If there is no unit then convert to biggest unit
  if(unit === undefined){
    return convertToBiggestBytes(value);
  }

  // Otherwise convert to the specified unit

  // Get the index of the unit, this directly corresponds to the power of 100
  const power = BYTE_TYPES.indexOf(unit);

  return {
    value: value / (Math.pow(1000, power)),
    label: unit
  }
}

export const toBytesString = (value: number, unit: ByteType | undefined = undefined): string => {
  const { value: convertedValue, label } = toBytes(value, unit);

  return `${Math.round(convertedValue*1000) / 1000} ${label}`;
}

export const getSmallestByteCategory = (bytesList: number[]): ByteType => {
  // Get the smallest value
  const smallestUnit = bytesList.reduce((acc, bytes) => {
    return Math.min(acc, bytes);
  }, Number.MAX_VALUE);

  // Get the smallest values unit
  const { value, label } = convertToBiggestBytes(smallestUnit);

  return label
}

/**
 * Convert a list to its smallest shared byte unit
 */
export const convertListBytes = (bytesList: number[] | any[]): ByteValue[] => {

  // Get the smallest unit
  const label = getSmallestByteCategory(bytesList);

  // Convert all the values to the smallest unit
  return bytesList.map((bytes) => {
    return toBytes(bytes, label);
  });
}
