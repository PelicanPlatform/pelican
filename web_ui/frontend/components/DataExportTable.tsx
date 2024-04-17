"use client"

import {
    Table,
    TableCell,
    TableBody,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    Typography,
    Box,
    BoxProps
} from '@mui/material';
import React, {FunctionComponent, ReactElement, useEffect, useMemo, useRef, useState} from "react";
import {Skeleton} from "@mui/material";

import {TableCellOverflow} from "@/components/Cell";

interface Capabilities {
    PublicReads: boolean;
    Reads: boolean;
    Writes: boolean;
    Listings: boolean;
    DirectReads: boolean;
  }

type ExportRes = { type: "s3", exports: S3ExportEntry[] } | { type: "posix", exports: PosixExportEntry[]};

interface ExportEntry {
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

export const RecordTable = ({ data }: { data: ExportRes }): ReactElement  => {
    return (
        <TableContainer>
            <Table sx={{tableLayout: "fixed"}}>
                <TableHead>
                    <TableRow>
                        <TableCell sx={{width: "20%"}}>Type</TableCell>
                        <TableCell sx={{width: "40%"}}>{data.type == "s3" ? "S3 Bucket Name" : "Local Path"}</TableCell>
                        <TableCell sx={{width: "40%"}}>Federation Path</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {data?.exports.map((record, index) => (
                        <TableRow key={record?.federation_prefix}>
                            <TableCellOverflow key={record.federation_prefix} sx={{width: "20%"}}>{data.type == null ? "NULL" : data.type.toUpperCase()}</TableCellOverflow>
                            <TableCellOverflow key={record.federation_prefix} sx={{width: "40%"}}>{data.type == "s3" ? ((record as S3ExportEntry).s3_bucket || "NULL") : ((record as PosixExportEntry)?.storage_prefix || "NULL")}</TableCellOverflow>
                            <TableCellOverflow key={record.federation_prefix} sx={{width: "40%"}}>{record?.federation_prefix == null ? "NULL" : record?.federation_prefix}</TableCellOverflow>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    )
}

export const DataExportTable = ({boxProps}: {boxProps?: BoxProps}) => {

    const [data, setData] = useState<ExportRes | undefined>(undefined);
    const [error, setError] = useState<string | undefined>(undefined);


    const getData = async () => {
        let response = await fetch("/api/v1.0/origin_ui/exports")
        if (response.ok) {
            const responseData = await response.json()
            setData(responseData)
        } else {
            setError("Failed to fetch config, response status: " + response.status)
        }
    }

    useEffect(() => {
        getData()
    }, [])

    if(error){
        return (
            <Box p={1}>
                <Typography sx={{color: "red"}} variant={"subtitle2"}>{error}</Typography>
            </Box>
        )
    }

    return (
        <Box sx={{backgroundColor: "#F6F6F6"}} {...boxProps}>
            {data ? <RecordTable data={data} /> : <Skeleton variant={"rectangular"} height={200} width={"100%"} />}
        </Box>
    )
}
