'use client';

import { createContext, Dispatch, useReducer } from 'react';
import { ReactNode } from 'react';
import { DateTime } from 'luxon';
import { TimeDuration, TimeDurationString } from '@/components';

const defaultGraphContext = {
  time: DateTime.fromISO('2024-01-01T00:00:00Z'),
  range: TimeDuration.fromString('1d'),
  resolution: TimeDuration.fromString('60m'),
  rate: TimeDuration.fromString('60m'),
};

export const GraphContext =
  createContext<GraphContextType>(defaultGraphContext);
export const GraphDispatchContext = createContext<Dispatch<GraphReducerAction>>(
  () => {}
);

export const GraphProvider = ({ children }: { children: ReactNode }) => {
  const [state, dispatch] = useReducer(graphReducer, defaultGraphContext);

  return (
    <GraphContext.Provider value={state}>
      <GraphDispatchContext.Provider value={dispatch}>
        {children}
      </GraphDispatchContext.Provider>
    </GraphContext.Provider>
  );
};

interface RangePreset {
  prevRange: TimeDurationString;
  nextRange: TimeDurationString;
  resolution: TimeDurationString;
  rate: TimeDurationString;
}

const rangeValues: Record<string, RangePreset> = {
  '1h': {
    prevRange: '1h',
    nextRange: '1d',
    resolution: '1m',
    rate: '1m',
  },
  '1d': {
    prevRange: '1h',
    nextRange: '1w',
    resolution: '30m',
    rate: '30m',
  },
  '1w': {
    prevRange: '1d',
    nextRange: '4w',
    resolution: '4h',
    rate: '4h',
  },
  '4w': {
    prevRange: '1w',
    nextRange: '1y',
    resolution: '12h',
    rate: '12h',
  },
  '1y': {
    prevRange: '4w',
    nextRange: '1y',
    resolution: '7d',
    rate: '7d',
  },
};

const updateRange = (state: GraphContextType, range: string) => {
  return {
    ...state,
    range: TimeDuration.fromString(range),
    resolution: TimeDuration.fromString(rangeValues[range].resolution),
    rate: TimeDuration.fromString(rangeValues[range].rate),
  };
};

const adjustRange = (
  state: GraphContextType,
  updateType: 'incrementTimeByRange' | 'decrementTimeByRange'
) => {
  let temptime;

  if (updateType === 'incrementTimeByRange') {
    temptime = state.time.plus(state.range.toDuration());
  } else {
    temptime = state.time.minus(state.range.toDuration());
  }

  if (state.range.type !== 'h') {
    temptime.set({ hour: 23, minute: 59, second: 59 });
  }

  return { ...state, time: temptime };
};

const calculateBestFitRange = (milliseconds: number): TimeDuration => {
  let range = '1h';
  if (milliseconds > 1000 * 60 * 60 * 24 * 365) {
    range = '1y';
  } else if (milliseconds > 1000 * 60 * 60 * 24 * 28) {
    range = '4w';
  } else if (milliseconds > 1000 * 60 * 60 * 24 * 7) {
    range = '1w';
  } else if (milliseconds > 1000 * 60 * 60 * 24) {
    range = '1d';
  }

  return TimeDuration.fromString(range);
};

function graphReducer(state: GraphContextType, action: GraphReducerAction) {
  let newState;
  switch (action.type) {
    case 'setTime':
      newState = { ...state, time: action.payload };
      break;
    case 'setRange':
      newState = updateRange(state, action.payload.toString());
      break;
    case 'setTimeRange':
      // Calculate the range that best fits the time range
      const range = calculateBestFitRange(
        action.payload.end.diff(action.payload.start).milliseconds
      );
      const updatedTimeState = { ...state, time: action.payload.end };
      newState = updateRange(updatedTimeState, range.toString());
      break;
    case 'incrementTimeByRange':
      newState = adjustRange(state, 'incrementTimeByRange');
      break;
    case 'decrementTimeByRange':
      newState = adjustRange(state, 'decrementTimeByRange');
      break;
    case 'incrementRange':
      // Get the next range value
      let nextRange = rangeValues[state.range.toString()].nextRange;
      newState = updateRange(state, nextRange);
      break;
    case 'decrementRange':
      // Get the previous range value
      let prevRange = rangeValues[state.range.toString()].prevRange;
      newState = updateRange(state, prevRange);
      break;

    default:
      newState = state;
      break;
  }

  // Update the current windows url to reflect the new state
  if (window !== undefined) {
    window.history.pushState(
      {},
      '',
      `?time=${newState.time.toISO()}&range=${newState.range.toString()}`
    );
  }

  return newState;
}

type GraphReducerAction =
  | setTimeAction
  | setRangeAction
  | setTimeRangeAction
  | incrementTimeByRange
  | decrementTimeByRange
  | incrementRange
  | decrementRange;

type setTimeRangeAction = {
  type: 'setTimeRange';
  payload: {
    start: DateTime;
    end: DateTime;
  };
};

type setTimeAction = {
  type: 'setTime';
  payload: DateTime;
};

type setRangeAction = {
  type: 'setRange';
  payload: TimeDuration;
};

type incrementTimeByRange = {
  type: 'incrementTimeByRange';
};

type decrementTimeByRange = {
  type: 'decrementTimeByRange';
};

type incrementRange = {
  type: 'incrementRange';
};

type decrementRange = {
  type: 'decrementRange';
};

// rate(http_requests_total[<rate>])[<range>:<resolution>]?time=<time>
interface GraphContextType {
  time: DateTime;
  range: TimeDuration;
  resolution: TimeDuration;
  rate: TimeDuration;
}

export default GraphProvider;
