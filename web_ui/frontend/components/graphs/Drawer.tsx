"use client"

import {Box, Button, FormControl, Grid, IconButton, InputLabel, MenuItem, Paper, Select} from "@mui/material";
import React, {useEffect, useState} from "react";
import {AutoGraphOutlined, CalendarMonth, QuestionMark, ReplayOutlined} from "@mui/icons-material";
import {DurationType, TimeDuration} from "@/components/graphs/prometheus";
import {DatePicker, LocalizationProvider} from "@mui/x-date-pickers";
import {AdapterLuxon} from "@mui/x-date-pickers/AdapterLuxon";
import TextField from "@mui/material/TextField";
import {DateTime} from "luxon";

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

function ReportPeriodInput({duration, setDuration, time, setTime}: {duration: TimeDuration, setDuration: Function, time: DateTime, setTime: Function}) {
    return (
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
    )
}

function RateInput({rate, setRate}: {rate: TimeDuration, setRate: Function}) {
    return (
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
                <IconButton href={"https://prometheus.io/docs/prometheus/latest/querying/functions/#rate"} size={"small"} target="_blank" rel="noopener noreferrer"><QuestionMark/></IconButton>
            </Grid>
        </Grid>
    )
}

function ResolutionInput({resolution, setResolution}: {resolution: TimeDuration, setResolution: Function}) {
    return (
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
                <IconButton href={"https://prometheus.io/docs/prometheus/latest/querying/examples/#subquery"} size={"small"} target="_blank" rel="noopener noreferrer"><QuestionMark/></IconButton>
            </Grid>
        </Grid>
    )
}

interface GraphDrawerProps {
    duration: TimeDuration;
    time: DateTime;
    setDuration: Function;
    setTime: Function;
    reset: Function;
    children: React.ReactNode;
}

function GraphDrawer({duration, time, setDuration, setTime, reset, children}: GraphDrawerProps) {

    const [reportPeriodHidden, setReportPeriodHidden] = useState<boolean>(true)
    const [graphSettingsHidden, setGraphSettingsHidden] = useState<boolean>(true)

    const [drawerOpen, setDrawerOpen] = useState<boolean>(false)

    useEffect(() => {
        setDrawerOpen(!reportPeriodHidden || !graphSettingsHidden)
    }, [reportPeriodHidden, graphSettingsHidden])

    return (
        <Paper elevation={drawerOpen ? 1 : 0} sx={{display: "flex", flexGrow: 1, flexDirection: "column", transition: "all 0.5s ease", backgroundColor: drawerOpen ? "#fff" : "#fff0" }}>
            <Box display={"flex"} flexGrow={1} mt={2} mb={0}>
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
                    <ReportPeriodInput duration={duration} setDuration={setDuration} time={time} setTime={setTime} />
                </DrawerBox>
                <DrawerBox hidden={graphSettingsHidden}>
                    {children}
                </DrawerBox>
            </Box>
        </Paper>
    )
}


export {GraphDrawer, RateInput, ResolutionInput}
