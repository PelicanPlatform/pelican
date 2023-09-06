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

import {useEffect, useState} from "react";
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    ChartOptions,
    ChartDataset,
} from 'chart.js';

import {BoxProps} from "@mui/material";

import {Line} from "react-chartjs-2";
import {Box, Skeleton, Typography} from "@mui/material";

import {query_rate, DataPoint} from "@/components/graphs/prometheus";
import {ChartData} from "chart.js";
import {Simulate} from "react-dom/test-utils";
import error = Simulate.error;

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
);

interface RateGraphProps {
    boxProps?: BoxProps;
    metric: string;
    rate?: string;
    duration?: string;
    resolution?: string;
    options?: ChartOptions<"line">
    datasetOptions?: Partial<ChartDataset<"line">>
}

export default function RateGraph({boxProps, metric, rate, duration, resolution, options, datasetOptions}: RateGraphProps) {

    let [data, setData] = useState<DataPoint[]>([])
    let [loading, setLoading] = useState<boolean>(true)
    let [error, setError] = useState<string>("")
    let [_rate, setRate] = useState(rate ? rate : "1h")
    let [_duration, setDuration] = useState(duration ? duration : "24h")
    let [_resolution, setResolution] = useState(resolution ? resolution : "1h")

    let chartData: ChartData<"line", any, any> = {
        datasets: [{
            "data": data,
            ...datasetOptions
        }]
    }

    function _setData(){
        query_rate(metric, _rate, _duration, _resolution)
            .then((response) => {
                setData(response)
                setLoading(false)
                if(response.length === 0){
                    let date = new Date(Date.now()).toLocaleTimeString()
                    setError(`No data returned by database as of ${date}; plot will auto-refresh`)
                } else {
                    setError("")
                }
            })
    }

    useEffect(() => {

        // Do the initial data fetch
        _setData()

        // Refetch the data every minute
        const interval = setInterval(() => _setData(), 60000);
        return () => clearInterval(interval);

    }, [])


    if(loading){
        return <Skeleton sx={{borderRadius: "1"}} variant={"rectangular"} width={"100%"} height={"100%"} />
    }

    return (
        <Box>
            <Box m={"auto"} {...boxProps}>
                <Line
                    data={chartData}
                    options={options}
                />
            </Box>
            <Box display={"flex"}>
                <Typography m={"auto"} color={"red"} variant={"body2"}>{error}</Typography>
            </Box>
        </Box>
    )

}
