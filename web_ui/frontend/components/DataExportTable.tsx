"use client"

import {green, grey, orange, red} from "@mui/material/colors";
import {
    Typography,
    Box,
    BoxProps,
    IconButton,
    Button,
    Grid,
    Tooltip,
    Pagination, Paper
} from '@mui/material';
import React, {FunctionComponent, ReactElement, useEffect, useMemo, useRef, useState} from "react";
import {Skeleton} from "@mui/material";

import {TableCellOverflow} from "@/components/Cell";
import {Edit, Warning, Check, Clear} from "@mui/icons-material";
import useSWR from "swr";

interface Capabilities {
    PublicReads: boolean;
    Reads: boolean;
    Writes: boolean;
    Listings: boolean;
    DirectReads: boolean;
  }

type ExportRes = { type: "s3", exports: S3ExportEntry[] } | { type: "posix", exports: PosixExportEntry[]};

type ExportEntryStatus = "Not Supported" | "Completed" | "Incomplete" | "Registration Error"

interface ExportEntry {
    status: ExportEntryStatus
    status_description: string;
    edit_url: string;
    federation_prefix: string;
    capabilities: Capabilities;
}

interface S3ExportEntry extends ExportEntry {
    s3_access_keyfile: string;
    s3_secret_keyfile: string;
    s3_bucket: string;
}

interface PosixExportEntry extends ExportEntry {
    storage_prefix: string;
    sentinel_location: string;
}

export const DataExportStatus = (
    {status, status_description, edit_url}: {status: ExportEntryStatus, status_description: string, edit_url: string}
) => {


    switch(status){
        case "Completed":
            return null;
        case "Incomplete":
            return (
                <Box sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    backgroundColor: red[50],
                    p:1,
                    borderRadius: 1
                }}>
                    <Box pr={1} my={"auto"}>
                        <Typography variant={"body2"}>{status_description}</Typography>
                    </Box>
                    <Box>
                        <Button variant={"contained"} color={"warning"} href={edit_url} endIcon={<Edit/>}>Complete Registration</Button>
                    </Box>
                </Box>
            )
        default:
            return (
                <Box sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    backgroundColor: red[50],
                    p:1,
                    borderRadius: 1
                }}>
                    <Box pr={1} my={"auto"}>
                        <Typography variant={"body2"}>{status}:{status_description}</Typography>
                    </Box>
                </Box>
            )
    }
}

export const CapabilitiesTable = ({capabilities}: {capabilities: Capabilities}) => {

    return (
        <Box>
            {Object.entries(capabilities).map(([key, value]) => {
                return (
                    <Tooltip title={value.toString()}>
                        <Box
                            sx={{
                                borderRadius: 1,
                                display: "flex",
                                justifyContent: "space-between",
                                py: .4,
                                px: 1,
                                mb: .2,
                                backgroundColor: value ? green[200] : orange[200],
                                border: "1px 1px solid black"
                            }}
                        >
                            <Typography variant={"body2"}>
                                {key}
                            </Typography>
                            <Box display={"flex"}>
                                {value ? <Check fontSize="small" /> : <Clear fontSize="small" />}
                            </Box>
                        </Box>
                    </Tooltip>
                )
            })}
        </Box>
    )
}

export const ValueLabel = ({value, label}: {value: string, label: string}) => {

    if(!value){
        return null
    }

    return (
        <Box display={"flex"} flexDirection={"column"}>
            <Typography sx={{backgroundColor: grey[200], mr: "auto", px: 1, borderRadius: .5}} variant={"caption"}>{label}</Typography>
            <Typography pl={.5} pt={.6} pb={.8} variant={"h6"} sx={{wordBreak: "break-all"}}>{value}</Typography>
        </Box>
    )
}

export const PosixDataExportCard = ({entry}: {entry: PosixExportEntry}) => {
    return (
        <Paper elevation={1}>
            {entry.status != "Completed" && <DataExportStatus {...entry}/>}
            <Grid container p={1}>
                <Grid item xs={9}>
                    <ValueLabel value={entry.federation_prefix} label={"Federation Prefix"}/>
                    <ValueLabel value={entry.storage_prefix} label={"Storage Prefix"}/>
                    <ValueLabel value={entry.sentinel_location} label={"Sentinel Location"}/>
                </Grid>
                <Grid item xs={3}>
                    <CapabilitiesTable {...entry}/>
                </Grid>
            </Grid>
        </Paper>
    )
}

export const S3DataExportCard = ({entry}: {entry: S3ExportEntry}) => {
    return (
        <Paper elevation={1}>
            {entry.status != "Completed" && <DataExportStatus {...entry}/>}
            <Grid container pt={1}>
                <Grid item xs={9}>
                    <ValueLabel value={entry.federation_prefix} label={"Federation Prefix"}/>
                    <ValueLabel value={entry.s3_bucket} label={"S3 Bucket"}/>
                </Grid>
                <Grid item xs={3}>
                    <CapabilitiesTable {...entry}/>
                </Grid>
            </Grid>
        </Paper>
    )
}

export const Paginator = ({data, page, setPage, pageSize}: {data: any[], page: number, pageSize: number, setPage: (p: number) => void}) => {
    if(data.length <= pageSize){
        return null
    }

    return (
        <Box display={"flex"} justifyContent={"center"} pb={1}>
            <Pagination count={Math.round(data.length / pageSize)} page={page} onChange={(e, p) => setPage(p)}></Pagination>
        </Box>
    )
}

export const RecordTable = ({ data }: { data: ExportRes }): ReactElement  => {

    const [page, setPage] = useState<number>(1);

    // Get the array values indicated by the current page and a pageSize of 2
    const entryPage: ExportEntry[] = useMemo(() => {
        const start = (page - 1) * 2
        const end = start + 2
        return Object.values(data.exports).slice(start, end)
    }, [page])

    switch (data.type) {
        case "s3":
            return (
                <>
                    {entryPage.map((entry, index) => (
                        <Box pb={1}>
                            <S3DataExportCard key={entry.federation_prefix} entry={entry as S3ExportEntry}/>
                        </Box>
                    ))}
                    <Paginator data={data.exports} page={page} pageSize={2} setPage={setPage}/>
                </>
            )
        case "posix":
            return (
                <>
                    {entryPage.map((entry, index) => (
                        <Box  pb={1}>
                            <PosixDataExportCard key={entry.federation_prefix} entry={entry as PosixExportEntry}/>
                        </Box>
                    ))}
                    <Paginator data={data.exports} page={page} pageSize={2} setPage={setPage}/>
                </>
            )
    }
}

const getExportData = async () : Promise<ExportRes> => {
    let response = await fetch("/api/v1.0/origin_ui/exports")
    if (response.ok) {
        const responseData = await response.json()
        return responseData
    } else {
        let message;
        try {
            const data = await response.json()
            message = data['msg']
        } catch (e) {
            message = response.statusText
        }
        throw new Error(`${response.status}: ${message}`)
    }
}

export const DataExportTable = ({boxProps}: {boxProps?: BoxProps}) => {

    const {data, error} = useSWR("getDataExport", getExportData)

    if(error){
        return (
            <Box p={1}>
                <Typography sx={{color: "red"}} variant={"subtitle2"}>{error.toString()}</Typography>
            </Box>
        )
    }

    return (
        <Box {...boxProps}>
            {data ? <RecordTable data={data} /> : <Skeleton variant={"rectangular"} height={200} width={"100%"} />}
        </Box>
    )
}
