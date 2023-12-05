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

import {useState} from "react";
import {
    ChartOptions,
    ChartDataset,
} from 'chart.js';

import {BoxProps} from "@mui/material";


import {query_basic, TimeDuration} from "@/components/graphs/prometheus";
import {ChartData} from "chart.js";
import Graph from "@/components/graphs/Graph";


interface LineGraphProps {
    boxProps?: BoxProps;
    metric: string;
    duration?: TimeDuration;
    resolution?: TimeDuration;
    options?: ChartOptions<"line">
    datasetOptions?: Partial<ChartDataset<"line">>
}

export default function LineGraph({ boxProps, metric, duration=new TimeDuration(31, "d"), resolution=new TimeDuration(1, "h"), options, datasetOptions}: LineGraphProps) {

    let [_duration, setDuration] = useState(duration)
    let [_resolution, setResolution] = useState(resolution)

    async function getData(){
        let chartData: ChartData<"line", any, any> = {
            datasets: [{
                data: await query_basic({metric: metric, duration:_duration, resolution:_resolution}),
                ...datasetOptions
            }]
        }

        return chartData
    }

    return (
        <Graph getData={getData} options={options} boxProps={boxProps}/>
    )

}
