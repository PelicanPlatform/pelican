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

import {useEffect, useState} from "react";
import {
    ChartOptions,
    ChartDataset,
    ChartData
} from 'chart.js';

import {DateTime} from "luxon";

import 'chartjs-adapter-luxon';

import {BoxProps, Button, FormControl, Grid, IconButton, InputLabel, MenuItem, Paper, Select} from "@mui/material";

import {Box} from "@mui/material";

import {query_rate, TimeDuration, DurationType} from "@/components/graphs/prometheus";
import {AutoGraphOutlined, CalendarMonth, QuestionMark, ReplayOutlined} from "@mui/icons-material";
import {DatePicker, LocalizationProvider} from "@mui/x-date-pickers";
import {AdapterLuxon} from "@mui/x-date-pickers/AdapterLuxon";
import TextField from "@mui/material/TextField";

const Graph = dynamic(
    () => import('@/components/graphs/Graph'),
    { ssr: false }
)

function DrawerBox({children, hidden=false}: {children: any, hidden: boolean}) {

    return (
        <Box
            sx={{
                display: "flex",
                overflow: "hidden",
                maxHeight: hidden ? 0 : "200px",
                m: hidden ? 0 : 2,
                pt: hidden ? 0 : 2,
                flexDirection: "column",
                transition: "all 0.2s ease",
            }}>
            {children}
        </Box>
    )
}


interface RateGraphDrawerProps {
    reset: Function;
    rate: TimeDuration;
    resolution: TimeDuration;
    duration: TimeDuration;
    time: DateTime;
    setRate: Function
    setResolution: Function
    setDuration: Function
    setTime: Function
}

function RateGraphDrawer({reset, rate, resolution, duration, time, setRate, setResolution, setDuration, setTime}: RateGraphDrawerProps) {

    const [reportPeriodHidden, setReportPeriodHidden] = useState<boolean>(true)
    const [graphSettingsHidden, setGraphSettingsHidden] = useState<boolean>(true)

    const [drawerOpen, setDrawerOpen] = useState<boolean>(false)

    useEffect(() => {
        setDrawerOpen(!reportPeriodHidden || !graphSettingsHidden)
    }, [reportPeriodHidden, graphSettingsHidden])

    return (
        <Paper elevation={drawerOpen ? 1 : 0} sx={{display: "flex", flexGrow: 1, flexDirection: "column", transition: "all 0.5s ease", backgroundColor: drawerOpen ? "#fff" : "#fff0" }}>
            <Box display={"flex"} flexGrow={1} m={1} mb={0}>
                <IconButton size={"small"} onClick={() => reset()}><ReplayOutlined /></IconButton>
                <Button
                    size={"small"}
                    variant="outlined"
                    startIcon={<CalendarMonth />}
                    onClick={() => {
                        setReportPeriodHidden(!reportPeriodHidden);
                        setGraphSettingsHidden(true)
                    }}
                >
                    Report Period
                </Button>
                <Button
                    size={"small"}
                    variant="outlined"
                    startIcon={<AutoGraphOutlined />}
                    onClick={() => {
                        setGraphSettingsHidden(!graphSettingsHidden);
                        setReportPeriodHidden(true)
                    }}
                    sx={{marginLeft: 1}}
                >
                    Graph Settings
                </Button>
            </Box>
            <Box>
                <DrawerBox hidden={reportPeriodHidden}>
                    <Grid container spacing={2}>
                        <Grid item xs={12} md={6}>
                            <FormControl fullWidth>
                                <InputLabel id="select-report-length-label">Report Length</InputLabel>
                                <Select
                                    labelId="select-report-length-label"
                                    id="select-report-length"
                                    label="Report Length"
                                    value={duration.value}
                                    onChange={(e) => setDuration(new TimeDuration(e.target.value as number, duration.type))}
                                >
                                    <MenuItem value={1}>Day</MenuItem>
                                    <MenuItem value={7}>Week</MenuItem>
                                    <MenuItem value={31}>Month</MenuItem>
                                </Select>
                            </FormControl>
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <LocalizationProvider dateAdapter={AdapterLuxon}>
                                <DatePicker sx={{width: "100%"}} label={"Report End"} value={time} onChange={d => {console.log(d); setTime(d)}} />
                            </LocalizationProvider>
                        </Grid>
                    </Grid>
                </DrawerBox>
                <DrawerBox hidden={graphSettingsHidden}>
                    <Grid container spacing={2}>
                        <Grid item xs={12}>
                            <Grid container spacing={1}>
                                <Grid item xs={6}>
                                    <FormControl fullWidth>
                                        <TextField
                                            label={"Rate Time Range"}
                                            type={"number"}
                                            inputProps={{min:0}}
                                            value={rate.value}
                                            onChange={(e) => setRate(new TimeDuration(parseInt(e.target.value), rate.type))}
                                        ></TextField>
                                    </FormControl>
                                </Grid>
                                <Grid item xs={5}>
                                    <FormControl fullWidth>
                                        <InputLabel id="select-report-length-label">Unit</InputLabel>
                                        <Select
                                            labelId="select-report-length-label"
                                            id="select-report-length"
                                            label="Report Length"
                                            value={rate.type}
                                            onChange={(e) => setRate(new TimeDuration(rate.value, e.target.value as DurationType))}
                                        >
                                            <MenuItem value={"m"}>Minute</MenuItem>
                                            <MenuItem value={"h"}>Hour</MenuItem>
                                            <MenuItem value={"d"}>Day</MenuItem>
                                        </Select>
                                    </FormControl>
                                </Grid>
                                <Grid item xs={1} m={"auto"}>
                                    <IconButton href={"https://prometheus.io/docs/prometheus/latest/querying/functions/#rate"} size={"small"}><QuestionMark/></IconButton>
                                </Grid>
                            </Grid>
                        </Grid>
                        <Grid item xs={12}>
                            <Grid container spacing={1}>
                                <Grid item xs={6}>
                                    <FormControl fullWidth>
                                        <TextField
                                            label={"Resolution"}
                                            type={"number"}
                                            inputProps={{min:0}}
                                            value={resolution.value}
                                            onChange={(e) => setResolution(new TimeDuration(parseInt(e.target.value), resolution.type))}
                                        ></TextField>
                                    </FormControl>
                                </Grid>
                                <Grid item xs={5}>
                                    <FormControl fullWidth>
                                        <InputLabel id="select-report-length-label">Unit</InputLabel>
                                        <Select
                                            labelId="select-report-length-label"
                                            id="select-report-length"
                                            label="Report Length"
                                            value={resolution.type}
                                            onChange={(e) => setResolution(new TimeDuration(resolution.value, e.target.value as DurationType))}
                                        >
                                            <MenuItem value={"m"}>Minute</MenuItem>
                                            <MenuItem value={"h"}>Hour</MenuItem>
                                            <MenuItem value={"d"}>Day</MenuItem>
                                        </Select>
                                    </FormControl>
                                </Grid>
                                <Grid item xs={1} m={"auto"}>
                                    <IconButton href={"https://prometheus.io/docs/prometheus/latest/querying/examples/#subquery"} size={"small"}><QuestionMark/></IconButton>
                                </Grid>
                            </Grid>
                        </Grid>
                    </Grid>
                </DrawerBox>
            </Box>
        </Paper>
    )
}

interface RateGraphProps {
    boxProps?: BoxProps;
    metric: string[];
    rate?: TimeDuration;
    duration?: TimeDuration;
    resolution?: TimeDuration;
    options?: ChartOptions<"line">
    datasetOptions?: Partial<ChartDataset<"line">> | Partial<ChartDataset<"line">>[];
}

export default function RateGraph({boxProps, metric, rate=new TimeDuration(3, "h"), duration=new TimeDuration(7, "d"), resolution=new TimeDuration(3, "h"), options={}, datasetOptions={}}: RateGraphProps) {

    let default_rate = rate
    let default_duration = duration
    let default_resolution = resolution

    let reset = () => {
        setRate(default_rate.copy())
        setDuration(default_duration.copy())
        setResolution(default_resolution.copy())
        setTime(DateTime.now())
    }


    let [_rate, setRate] = useState(rate)
    let [_duration, _setDuration] = useState(duration)
    let [_resolution, setResolution] = useState(resolution)
    let [_time, _setTime] = useState<DateTime>(DateTime.now().plus({ days: 1 }).set({ hour: 0, minute: 0, second: 0, millisecond: 0 }))

    // Create some reasonable defaults for the graph
    let setDuration = (duration: TimeDuration) => {
        if(duration.value == 1){
            setRate(new TimeDuration(30, "m"))
            setResolution(new TimeDuration(30, "m"))
        } else if(duration.value == 7){
            setRate(new TimeDuration(3, "h"))
            setResolution(new TimeDuration(3, "h"))
        } else if(duration.value == 31){
            setRate(new TimeDuration(12, "h"))
            setResolution(new TimeDuration(12, "h"))
        }

        _setDuration(duration)
    }

    let setTime = (time: DateTime) => {
        _setTime(time.set({ hour: 0, minute: 0, second: 0, millisecond: 0 }))
    }


    async function getData(){
        let chartData: ChartData<"line", any, any> = {
            datasets: await Promise.all(metric.map(async (metric, index) => {

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

                return {
                    data: (await query_rate({metric: `${metric}`, rate:_rate, duration:_duration, resolution:_resolution, time:_time})),
                    ...datasetOption
                }
            }))
        }

        return chartData
    }

    return (
        <Graph
            getData={getData}
            drawer={<RateGraphDrawer
                        reset={reset}
                        duration={_duration}
                        setDuration={setDuration}
                        rate={_rate}
                        setRate={setRate}
                        resolution={_resolution}
                        setResolution={setResolution}
                        time={_time}
                        setTime={setTime}
                    />}
            options={options} boxProps={boxProps}
        />
    )
}
