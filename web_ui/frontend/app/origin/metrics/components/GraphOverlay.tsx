'use client';

import { useContext, ReactNode, useMemo, useState, useEffect, useCallback } from 'react';
import { Box, Button, IconButton, MenuItem, Select, Typography } from '@mui/material';
import {DateTimePicker} from '@mui/x-date-pickers';
import {KeyboardArrowLeft, KeyboardArrowRight} from '@mui/icons-material';

import {GraphContext, GraphDispatchContext} from './GraphContext';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import { TimeDuration } from '@/components';
import { grey } from '@mui/material/colors';
import { DateTime } from 'luxon';

export const GraphOverlay = ({children}: {children: ReactNode}) => {

  const graphContext = useContext(GraphContext);
  const dispatch = useContext(GraphDispatchContext);

  const graphStart = useMemo(() => {
    return graphContext.time.minus(graphContext.range.toDuration())
  }, [graphContext.time, graphContext.range]);

  const format = useMemo(() => {
    return getFormatString([graphContext.time, graphStart])
  }, [graphContext.time, graphContext])

  const handleKeydown = useCallback((e: KeyboardEvent) => {
    switch (e.key) {
      case "ArrowLeft":
        dispatch({type: 'decrementTimeByRange'})
        break;
      case "ArrowRight":
        dispatch({type: 'incrementTimeByRange'})
        break;
      case "ArrowUp":
        dispatch({type: 'incrementRange'})
        break;
      case "ArrowDown":
        dispatch({type: 'decrementRange'})
        break;
    }
  }, [])

  // Capture arrow keys to adjust timeframe
  useEffect(() => {
    document.addEventListener('keydown', handleKeydown)

    return () => {
      document.removeEventListener('keydown', handleKeydown)
    }
  }, [])

  return (
    <>
      <Box display={"flex"} justifyContent={"space-between"} position={"sticky"}>
        <StringUpdateViewer>
          {graphStart.toFormat(format)} - {graphContext.time.toFormat("f")}
        </StringUpdateViewer>
        <Box display={"flex"}>
          <TimeRangeSelector />
          <DateTimePickerWithArrows/>
        </Box>
      </Box>
      {children}
    </>
  )
}

/**
 * Returns a reasonably verbose string format based on the time
 */
const getFormatString = (dateTimes: DateTime[]) => {

  // If the dateTime is from today
  if(dateTimes[0].hasSame(dateTimes[1], 'day')){
    return "HH:mm";
  }

  // If the dateTime is from the same year
  if(dateTimes[0].hasSame(dateTimes[1], 'year')){
    return "L/d";
  }

  // Else return a verbose option
  return "L/d/y";
}

/**
 * Shows the passed in date string and flashes darker on change
 */
const StringUpdateViewer = ({ children }: { children: ReactNode }) => {

  const [flash, setFlash] = useState(false);

  useEffect(() => {
    setFlash(true);
    setTimeout(() => {
      setFlash(false);
    }, 200);
  }, [children]);

  return (
    <Box
      bgcolor={flash ? grey[300] : grey[100]}
      px={2}
      py={1}
      my={1}
      display={"flex"}
      borderRadius={1}
      sx={{ transition: 'background-color 0.2s ease-out' }}
    >
      <Typography sx={{m: 'auto'}} variant={"h6"}>{children}</Typography>
    </Box>
  );
};

const DateTimePickerWithArrows = () => {

  const graphContext = useContext(GraphContext);
  const dispatch = useContext(GraphDispatchContext);

  return (
    <Box display={"flex"} mb={"auto"} mt={1}>
      <Box display={"flex"}>
        <Button
          variant={"outlined"}
          onClick={() => {
            dispatch({type: 'decrementTimeByRange'})
          }}
          sx={{height: "100%"}}
        >
          <KeyboardArrowLeft/>
        </Button>
        <Box sx={{mx:1}}>
          <DateTimePicker
            value={graphContext.time}
            onChange={(value) => {
              if(value){
                dispatch({type: 'setTime', payload: value})
              }
            }}
            slotProps={{textField: { sx: { minWidth: 120 }, size: "small"}}}
          />
        </Box>
        <Button
          variant={"outlined"}
          onClick={() => {
            dispatch({type: 'incrementTimeByRange'})
          }}
          sx={{height: "100%"}}
        >
          <KeyboardArrowRight/>
        </Button>
      </Box>
    </Box>
  )
}

const TimeRangeItems = {
  "Hour": "1h",
  "Day": "1d",
  "Week": "1w",
  "4 Weeks": "4w",
  "Year": "1y",
}

const TimeRangeSelector = () => {

  const graphContext = useContext(GraphContext);
  const dispatch = useContext(GraphDispatchContext);

  return (
    <FormControl sx={{ m: 1, minWidth: 120 }} size="small">
      <InputLabel id="graph-range-label">Graph Range</InputLabel>
      <Select
        labelId="graph-range-label"
        id="graph-range"
        value={graphContext.range.toString()}
        label="Graph Range"
        onChange={(e) => {
          dispatch({type: 'setRange', payload: TimeDuration.fromString(e.target.value as string)})
        }}
      >
        {Object.entries(TimeRangeItems).map(([key, value]) => {
            return <MenuItem key={value} value={value}>{key}</MenuItem>
        })}
      </Select>
    </FormControl>
  )
}
