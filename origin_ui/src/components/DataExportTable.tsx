import {Table, TableCell, TableBody, TableContainer, TableHead, TableRow, Paper, Typography, Box} from '@mui/material';
import React, {FunctionComponent, ReactElement, useEffect, useMemo, useRef, useState} from "react";
import {Skeleton} from "@mui/material";



interface Record {
    [key: string]: string | number | boolean | null
}

interface ExportData extends Record {
    "Type": string
    "Local Path": string
    "Routing Key": string
}

export const TableCellOverflow: FunctionComponent<any> = ({ children, ...props }) => {

    const cellRef = useRef<HTMLTableCellElement>(null);
    const [overflow, setOverflow] = useState<boolean>(false);

    useEffect(() => {
        if(cellRef.current) {
            setOverflow(cellRef.current.scrollWidth > cellRef.current.clientWidth)
        }
    }, [])

    return (
        <TableCell
            ref={cellRef}
            sx={{
                overflowX: "scroll",
                whiteSpace: "nowrap",
                boxShadow: overflow ? "inset -13px 0px 20px -21px rgba(0,0,0,0.75)" : "none",
                ...props?.sx
        }}>
            {children}
        </TableCell>
    )
}

export const RecordTable = ({ data }: { data: Record[] }): ReactElement  => {
    return (
        <TableContainer>
            <Table sx={{tableLayout: "fixed"}}>
                <TableHead>
                    <TableRow>
                        {Object.keys(data[0]).map((key, index) => (
                            <TableCell key={index} sx={{width: index == 0 ? "20%" : "40%"}}>{key}</TableCell>
                        ))}
                    </TableRow>
                </TableHead>
                <TableBody>
                    {data.map((record, index) => (
                        <TableRow key={index}>
                            {Object.values(record).map((value, index) => (
                                <TableCellOverflow key={index} sx={{width: index == 0 ? "20%" : "40%"}}>{value == null ? "NULL" : value}</TableCellOverflow>
                            ))}
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
    )
}


export const DataExportTable = () => {

    const [data, setData] = useState<ExportData[] | undefined>(undefined);
    const [error, setError] = useState<string | undefined>(undefined);


    const getData = async () => {
        let response = await fetch("/api/v1.0/config")
        if (response.ok) {
            const responseData = await response.json()

            setData([{
                "Type": "POSIX",
                "Local Path": ["", undefined].includes(responseData?.Xrootd?.Mount) ? "NULL" : responseData?.Xrootd?.Mount,
                "Routing Key": ["", undefined].includes(responseData?.Origin?.NamespacePrefix) ? "NULL" : responseData?.Origin?.NamespacePrefix
            }])

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
        <>
            {data ? <RecordTable data={data} /> : <Skeleton variant={"rectangular"} height={200} width={"100%"} />}
        </>
    )
}
