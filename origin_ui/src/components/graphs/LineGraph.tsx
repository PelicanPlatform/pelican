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

import {Line} from "react-chartjs-2";
import {Skeleton} from "@mui/material";

import {query_basic, DataPoint} from "@/components/graphs/prometheus";
import {ChartData} from "chart.js";

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
);

interface LineGraphProps {
    metric: string;
    duration?: string;
    resolution?: string;
    options?: ChartOptions<"line">
    datasetOptions?: Partial<ChartDataset<"line">>
}

export default function LineGraph({metric, duration, resolution, options, datasetOptions}: LineGraphProps) {

    let [data, setData] = useState<DataPoint[]>([])
    let [_duration, setDuration] = useState(duration ? duration : "24h")
    let [_resolution, setResolution] = useState(resolution ? resolution : "1h")

    let chartData: ChartData<"line", any, any> = {
        datasets: [{
            "data": data,
            ...datasetOptions
        }]
    }

    useEffect(() => {
        query_basic(metric, _duration, _resolution)
            .then((response) => {
                setData(response)
            })
    }, [])

    if(data.length === 0){
        return <Skeleton sx={{borderRadius: "1"}} variant={"rectangular"} width={"100%"} height={"100%"} />
    }

    return (
        <Line
            data={chartData}
            options={options}
        >
        </Line>
    )

}
