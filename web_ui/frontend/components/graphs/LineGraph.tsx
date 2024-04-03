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

"use client"

import dynamic from "next/dynamic";
import React, {useCallback, useState} from "react";
import {
    ChartOptions,
    ChartDataset,
} from 'chart.js';
import {ChartData} from "chart.js";
import {DateTime} from "luxon";
import {BoxProps, Grid} from "@mui/material";

import {query_basic, query_rate, TimeDuration} from "@/components/graphs/prometheus";
import {GraphDrawer, RateInput, ResolutionInput} from "@/components/graphs/Drawer";
const Graph = dynamic(
    () => import('@/components/graphs/Graph'),
    { ssr: false }
)

interface RateGraphDrawerProps {
    reset: Function;
    resolution: TimeDuration;
    duration: TimeDuration;
    time: DateTime;
    setResolution: Function
    setDuration: Function
    setTime: Function
}

function LineGraphDrawer({reset, resolution, duration, time, setResolution, setDuration, setTime}: RateGraphDrawerProps) {
    return (
        <GraphDrawer duration={duration} time={time} setDuration={setDuration} setTime={setTime} reset={reset}>
            <Grid container spacing={2}>
                <Grid item xs={12}>
                    <ResolutionInput resolution={resolution} setResolution={setResolution} />
                </Grid>
            </Grid>
        </GraphDrawer>
    )
}

interface LineGraphProps {
    boxProps?: BoxProps;
    metrics: string[];
    duration?: TimeDuration;
    resolution?: TimeDuration;
    options?: ChartOptions<"line">
    datasetOptions?: Partial<ChartDataset<"line">> | Partial<ChartDataset<"line">>[];
}

async function getData(
    metrics: string[],
    duration: TimeDuration,
    resolution: TimeDuration,
    time: DateTime,
    datasetOptions: Partial<ChartDataset<"line">> | Partial<ChartDataset<"line">>[]
) {
    let chartData: ChartData<"line", any, any> = {
        datasets: await Promise.all(metrics.map(async (metric, index) => {

            let datasetOption: Partial<ChartDataset<"line">> = {}
            if(datasetOptions instanceof Array){
                try {
                    datasetOption = datasetOptions[index]
                } catch (e) {
                    console.error("datasetOptions is an array, but the number of elements < the number of metrics")
                }
            } else {
                datasetOption = datasetOptions
            }

            let updatedTime = time
            if (updatedTime.hasSame(DateTime.now(), "day")) {
                updatedTime = DateTime.now()
            }

            return {
                data: (await query_basic({metric, duration:duration, resolution:resolution, time:updatedTime})),
                ...datasetOption
            }
        }))
    }

    return chartData
}

export default function LineGraph({ boxProps, metrics, duration=new TimeDuration(31, "d"), resolution=new TimeDuration(1, "h"), options, datasetOptions = {}}: LineGraphProps) {

    let reset = useCallback(() => {
        setDuration(duration.copy())
        setResolution(resolution.copy())
        setTime(DateTime.now())
    }, [duration, resolution])

    let [_duration, setDuration] = useState(duration)
    let [_resolution, setResolution] = useState(resolution)
    let [_time, setTime] = useState<DateTime>(DateTime.now())

    return (
        <Graph
            getData={() => getData(metrics, _duration, _resolution, _time, datasetOptions)}
            options={options}
            drawer={<LineGraphDrawer
                reset={reset}
                duration={_duration}
                setDuration={setDuration}
                resolution={_resolution}
                setResolution={setResolution}
                time={_time}
                setTime={setTime}
            />}
            boxProps={boxProps}
        />
    )

}
