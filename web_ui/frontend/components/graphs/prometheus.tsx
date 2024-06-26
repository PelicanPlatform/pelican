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

import { ChartData } from 'chart.js';

import { DateTime } from 'luxon';

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

export class TimeDuration {
  value: number;
  type: DurationType;

  constructor(value: number, type: DurationType) {
    this.value = value;
    this.type = type;
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

export interface getDataFunction {
  (): Promise<ChartData<'line', any, any>>;
}

export interface DataPoint {
  x: number;
  y: number;
}

export async function query_raw(
  query: string,
  time?: Number
): Promise<DataPoint[]> {
  const url = new URL(window.location.origin + '/api/v1.0/prometheus/query');
  url.searchParams.append('query', query);
  if (time) {
    url.searchParams.append('time', time.toString());
  }

  let response = await fetch(url.href);

  if (response.status !== 200) {
    throw new Error(`Prometheus query returned status ${response.status}`);
  }

  let json = await response.json();

  if (json.status !== 'success') {
    throw new Error(`Prometheus query returned status ${json.status}`);
  }

  if (json.data.result.length == 0) {
    return [];
  }

  // This will return the list of time and value tuples [1693918800,"0"],[1693919100,"0"]...
  let prometheusTuples = json.data.result[0].values;

  // Chart.js expects milliseconds since epoch
  let data: DataPoint[] = prometheusTuples.map((tuple: any) => {
    return { x: tuple[0] * 1000, y: parseFloat(tuple[1]) };
  });

  return data;
}

interface QueryBasicOptions {
  metric: string;
  duration: TimeDuration;
  resolution: TimeDuration;
  time?: DateTime;
}

export async function query_basic({
  metric,
  duration,
  resolution,
  time,
}: QueryBasicOptions): Promise<DataPoint[]> {
  let query = `${metric}[${duration.toString()}:${resolution.toString()}]`;
  return query_raw(query, time?.toSeconds());
}

interface QueryRateOptions {
  metric: string;
  rate: TimeDuration;
  duration: TimeDuration;
  resolution: TimeDuration;
  time?: DateTime;
}

export async function query_rate({
  metric,
  rate,
  duration,
  resolution,
  time,
}: QueryRateOptions): Promise<DataPoint[]> {
  let query = `rate(${metric}[${rate.toString()}])[${duration.toString()}:${resolution.toString()}]`;
  return query_raw(query, time?.toSeconds());
}
