/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

import { ChartData, ChartDataset } from 'chart.js';

import { DateTime, Duration } from 'luxon';
import { TypeOrTypeFunction } from '@/helpers/util';

export interface DataPoint {
  x: number;
  y: number;
}

interface ErrorResponse {
  status: 'error';
  errorType: 'bad_data' | 'timeout' | 'partial_result' | 'execution_error';
  error: string;
}

export interface SuccessResponse<T extends ResponseData> {
  status: 'success';
  data: T;
}

export interface VectorResult {
  metric: Record<string, string>;
  value: DataTuple;
}

export interface MatrixResult {
  metric: Record<string, string>;
  values: DataTuple[];
}

export type Result = MatrixResult | VectorResult;

export type DataTuple = [number, string];

export interface MatrixResponseData {
  resultType: 'matrix';
  result: MatrixResult[];
}

export interface VectorResponseData {
  resultType: 'vector';
  result: VectorResult[];
}

export type ResponseData = MatrixResponseData | VectorResponseData;

export interface getDataProps {
  range: TimeDuration;
  resolution: TimeDuration;
  time: DateTime;
}

export type getDataFunction = (
  props: getDataProps
) => Promise<ChartDataset<any, any>>;

export interface getRateDataProps extends getDataProps {
  rate: TimeDuration;
}

export type getRateDataFunction = (
  props: getRateDataProps
) => Promise<ChartDataset<any, any>>;

export type getDataWrapperFunction = () => Promise<ChartDataset<any, any>>;

let getTimeDuration = (value: string, defaultValue: number = 1) => {
  let _value = value.match(/\d+/);
  if (_value) {
    return parseInt(_value[0]);
  }

  console.error(
    'Invalid time duration, using default value: ' + defaultValue.toString()
  );
  return defaultValue;
};

let getDurationType = (value: string, defaultType: string = 'h') => {
  let _type = value.match(/\D+/);
  if (_type) {
    return _type[0];
  }

  console.error(
    `Invalid time duration type (${value}), using default value: ` +
      defaultType.toString()
  );
  return defaultType;
};

export type DurationType = 'ms' | 's' | 'm' | 'h' | 'd' | 'w' | 'y';

export type TimeDurationString = `${number}${DurationType}`;

export class TimeDuration {
  value: number;
  type: DurationType;

  constructor(value: number, type: DurationType) {
    this.value = value;
    this.type = type;
  }

  toDuration(): Duration {
    switch (this.type) {
      case 'ms':
        return Duration.fromMillis(this.value);
      case 's':
        return Duration.fromObject({ seconds: this.value });
      case 'm':
        return Duration.fromObject({ minutes: this.value });
      case 'h':
        return Duration.fromObject({ hours: this.value });
      case 'd':
        return Duration.fromObject({ days: this.value });
      case 'w':
        return Duration.fromObject({ weeks: this.value });
      case 'y':
        return Duration.fromObject({ years: this.value });
      default:
        throw new Error('Invalid duration type');
    }
  }

  toString() {
    return `${this.value}${this.type}`;
  }

  static fromString(value: string) {
    let _value = getTimeDuration(value);
    let _type = getDurationType(value) as DurationType;

    return new TimeDuration(_value, _type);
  }

  copy() {
    return new TimeDuration(this.value, this.type);
  }
}

export async function query_raw<T extends ResponseData>(
  query: string,
  time?: Number
): Promise<SuccessResponse<T>> {
  const url = new URL(window.location.origin + '/api/v1.0/prometheus/query');
  url.searchParams.append('query', query);
  if (time) {
    url.searchParams.append('time', time.toString());
  }

  let response = await fetch(url.href);
  if (response.status !== 200) {
    throw new Error(`Prometheus query returned status ${response.status}`);
  }

  let json = (await response.json()) as Response;

  if (json.status !== 'success') {
    throw new Error(json.error);
  }

  return json as SuccessResponse<T>;
}

interface QueryParameters {
  resolution: TimeDuration;
  rate: TimeDuration;
  time: DateTime;
  range: TimeDuration;
}

interface QueryOptions extends QueryParameters {
  metric: string;
}

type QueryBasicOptions = Omit<QueryOptions, 'rate'> & {
  time?: DateTime;
};

export async function query_basic({
  metric,
  range,
  resolution,
  time,
}: QueryBasicOptions): Promise<DataPoint[]> {
  const query = `${metric}[${range.toString()}:${resolution.toString()}]`;
  const queryResponse = await query_raw<MatrixResponseData>(
    query,
    time?.toSeconds()
  );
  return prometheusResultToDataPoints(queryResponse);
}

export const prometheusResultToDataPoints = (
  response: SuccessResponse<MatrixResponseData>
): DataPoint[] => {
  const result = response.data.result;

  if (result.values.length === 0) {
    return [];
  }

  // This will return the list of time and value tuples [1693918800,"0"],[1693919100,"0"]...
  let prometheusTuples = result[0].values;

  // Chart.js expects milliseconds since epoch
  let data: DataPoint[] = prometheusTuples.map((tuple: any) => {
    return { x: tuple[0] * 1000, y: parseFloat(tuple[1]) };
  });

  return data;
};

type QueryRateOptions = QueryOptions & {
  time?: DateTime;
};

export async function query_rate({
  metric,
  rate,
  range,
  resolution,
  time,
}: QueryRateOptions): Promise<SuccessResponse<MatrixResponseData>> {
  // Add a default time
  if (time == undefined) {
    time = DateTime.now();
  }

  const query = `rate(${metric}[${rate.toString()}])[${range.toString()}:${resolution.toString()}]`;
  return await query_raw(query, time?.toSeconds());
}

export type Response =
  | SuccessResponse<MatrixResponseData | VectorResponseData>
  | ErrorResponse;

export interface PrometheusQuery {
  value: string;
  datasetOptions?: TypeOrTypeFunction<Partial<ChartDataset<'line'>>>;
}

export const replaceQueryParameters = (
  q: string,
  qp: Partial<Omit<QueryOptions, 'time'>>
): string => {
  Object.keys(qp).forEach((key) => {
    const keyValue = qp[key as keyof typeof qp];
    if (keyValue instanceof TimeDuration) {
      q = q.replace(
        new RegExp('\\$\\{' + key + '\\}', 'g'),
        keyValue.toString()
      );
    }
  });
  return q;
};

/** Takes a prometheus response and fills in null values with 0 */
export const fillMatrixNulls = (
  defaultValue: any,
  data: MatrixResponseData
): MatrixResponseData => {
  let longestIndex = 0;
  let longestLength = 0;
  data.result.forEach((result, index) => {
    let values = result.values;
    if (values.length > longestLength) {
      longestLength = values.length;
      longestIndex = index;
    }
  });

  let longestValues = data.result[longestIndex].values;
  let timeKeys = longestValues.map((value) => value[0]);

  // Fill in the null values with 0 for the times that are missing otherwise
  data.result.forEach((result) => {
    result.values = fillArrayNulls(defaultValue, timeKeys, result.values);
  });

  return data;
};

export const fillArrayNulls = (
  defaultValue: any,
  timeKeys: number[],
  array: [number, string][]
): [number, string][] => {
  // If they are the same length there is nothing to be done
  if (timeKeys.length == array.length) {
    return array;
  }

  // Create an empty struct to be filled in by the partial array
  let newStructure: Record<number, string> = {};
  timeKeys.forEach((key) => {
    newStructure[key] = defaultValue;
  });

  // Fill in the struct from the partial array
  array.forEach(([key, value]) => {
    newStructure[key] = value;
  });

  // Convert the struct back into an array
  return Object.entries(newStructure).map(([key, value]) => {
    return [parseInt(key), value];
  });
};

/**
 * Build a prometheus metric string from a metric name and a set of key value pairs
 * Results in something like: metric{key1="value1",key2="value2"}
 */
export const buildMetric = (
  metric: string,
  args: Record<
    string,
    string | { comparator: '=' | '!='; value: string } | undefined
  >
) => {
  // Verify the metric name is valid
  if (!metric.match(/^[a-zA-Z_:][a-zA-Z0-9_:]*$/)) {
    throw new Error(`Invalid metric name: ${metric}`);
  }

  // Verify the key names are valid
  if (
    !Object.keys(args).every((key) => key.match(/^[a-zA-Z_][a-zA-Z0-9_]*$/))
  ) {
    throw new Error(`Invalid key name in metric: ${metric}`);
  }

  const labels = Object.entries(args).reduce((acc: string[], [key, value]) => {
    if (typeof value === 'string') {
      acc.push(`${key}="${value}"`);
    } else if (value === undefined) {
    } else {
      acc.push(`${key}${value.comparator}"${value.value}"`);
    }
    return acc;
  }, []);

  let labelString = '';
  if (labels.length > 0) {
    labelString = `{${labels.join(',')}}`;
  }

  return metric + labelString;
};
