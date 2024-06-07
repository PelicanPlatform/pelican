"use client"

import {green, grey, orange, red} from "@mui/material/colors";
import {
    Typography,
    Box,
    BoxProps,
    Button,
    Grid,
    Tooltip,
    Pagination, Paper,
    Alert
} from '@mui/material';
import React, {ReactElement, useEffect, useMemo, useRef, useState} from "react";
import {Skeleton} from "@mui/material";

import {Edit, Warning, Check, Clear} from "@mui/icons-material";
import useSWR from "swr";
import {getErrorMessage} from "@/helpers/util";

interface Capabilities {
    PublicReads: boolean;
    Reads: boolean;
    Writes: boolean;
    Listings: boolean;
    DirectReads: boolean;
  }


type RegistrationStatus = "Not Supported" | "Completed" | "Incomplete" | "Registration Error"

type ExportResCommon = {
    status: RegistrationStatus;
    statusDescription: string;
    editUrl: string;
}

type ExportRes = ExportResCommon & ({ type: "s3", exports: S3ExportEntry[] } | { type: "posix", exports: PosixExportEntry[]});

interface ExportEntry {
    status: RegistrationStatus
    statusDescription: string;
    editUrl: string;
    federationPrefix: string;
    capabilities: Capabilities;
}

interface S3ExportEntry extends ExportEntry {
    s3AccessKeyfile: string;
    s3SecretKeyfile: string;
    s3Bucket: string;
}

interface PosixExportEntry extends ExportEntry {
    storagePrefix: string;
    sentinelLocation: string;
}

export const DataExportStatus = (
    {status, statusDescription, editUrl}: {status: RegistrationStatus, statusDescription: string, editUrl: string}
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
                        <Typography variant={"body2"}>{statusDescription}</Typography>
                    </Box>
                    <Box>
                        <Button variant={"contained"} color={"warning"} href={editUrl} endIcon={<Edit/>}>Complete Registration</Button>
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
                        <Typography variant={"body2"}>{status}:{statusDescription}</Typography>
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
                    <Tooltip title={value.toString()} key={key}>
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
                    <ValueLabel value={entry.federationPrefix} label={"Federation Prefix"}/>
                    <ValueLabel value={entry.storagePrefix} label={"Storage Prefix"}/>
                    <ValueLabel value={entry.sentinelLocation} label={"Sentinel Location"}/>
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
                    <ValueLabel value={entry.federationPrefix} label={"Federation Prefix"}/>
                    <ValueLabel value={entry.s3Bucket} label={"S3 Bucket"}/>
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
                        <Box key={entry.federationPrefix} pb={1}>
                            <S3DataExportCard entry={entry as S3ExportEntry}/>
                        </Box>
                    ))}
                    <Paginator data={data.exports} page={page} pageSize={2} setPage={setPage}/>
                </>
            )
        case "posix":
            return (
                <>
                    {entryPage.map((entry, index) => (
                        <Box key={entry.federationPrefix} pb={1}>
                            <PosixDataExportCard entry={entry as PosixExportEntry}/>
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
        throw new Error(await getErrorMessage(response))
    }
}

export const DataExportTable = ({boxProps}: {boxProps?: BoxProps}) => {
    const [fromUrl, setFromUrl] = useState<string|undefined>(undefined)
    const {data, error} = useSWR("getDataExport", getExportData)

    useEffect(() => {
      setFromUrl(window.location.href)
    }, [])

    if(error){
        return (
            <Box p={1}>
                <Typography sx={{color: "red"}} variant={"subtitle2"}>{error.toString()}</Typography>
            </Box>
        )
    }

    const dataWFromUrl = data
    if (fromUrl) {
        if (dataWFromUrl?.editUrl) {
            try {
                const editUrl = new URL(dataWFromUrl?.editUrl)
                editUrl.searchParams.append("fromUrl", fromUrl)
                dataWFromUrl.editUrl = editUrl.toString()
            } catch (error) {
                console.log("editUrl is not a valid url: ", error)
            }
        }
        if (dataWFromUrl?.exports) {
            dataWFromUrl.exports.map((val) => {
                try {
                    const editUrl = new URL(val?.editUrl)
                    editUrl.searchParams.append("fromUrl", fromUrl)
                    val.editUrl = editUrl.toString()
                    return val
                } catch (error) {
                    console.log("editUrl is not a valid url: ", error)
                    return val
                }
            });
        }
    }

    return (
        <Box {...boxProps}>
            <Typography pb={1} variant={"h5"} component={"h3"}>Origin</Typography>
            {
                (dataWFromUrl && dataWFromUrl.status) && dataWFromUrl.status != "Completed" ?
                <DataExportStatus status={dataWFromUrl.status} statusDescription={dataWFromUrl.statusDescription} editUrl={dataWFromUrl.editUrl} />
                :
                <Alert severity="success">Registration Completed</Alert>
            }

            <Typography pt={2} pb={1} variant={"h5"} component={"h3"}>Namespaces</Typography>
            {dataWFromUrl ? <RecordTable data={dataWFromUrl} /> : <Skeleton variant={"rectangular"} height={200} width={"100%"} />}
        </Box>
    )
}
