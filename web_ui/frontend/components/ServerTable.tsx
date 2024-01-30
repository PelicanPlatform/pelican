import {Table, TableCell, TableBody, TableContainer, TableHead, TableRow, Paper, Typography, Box} from '@mui/material';
import React, {
    FunctionComponent,
    ReactElement,
    ReactNode,
    useCallback,
    useEffect,
    useMemo,
    useRef,
    useState
} from "react";
import {Skeleton} from "@mui/material";
import Link from "next/link";

import DataTable, {Record} from "@/components/DataTable";
import {TableCellOverflow} from "@/components/Cell";


interface ExportData extends Record {
    "Type": string
    "Local Path": string
    "Namespace Prefix": string
}

const TableCellOverflowLink: React.JSX.ElementType = ({ children, ...props }) => {

    console.log(children)

    if (children === null){
        children = ""
    }

    return (
        <TableCellOverflow sx={{color: "blue", cursor: "pointer"}} {...props}>
            <Link href={children as string}>
                {children}
            </Link>
        </TableCellOverflow>
    )
}



interface Server extends Record {
    name: string
    authUrl: string
    url: string
    webUrl: string
    type: string
    latitude: number
    longitude: number
}


interface ServerTableProps {
    type?: "cache" | "origin"
}

export const ServerTable = ({type} : ServerTableProps) => {

    const [data, setData] = useState<Server[] | undefined>(undefined);
    const [error, setError] = useState<string | undefined>(undefined);

    const keyToName = {
        "name": {
            name: "Name",
            cellNode: TableCellOverflow
        },
        "authUrl": {
            name: "Auth URL",
            cellNode: TableCellOverflowLink
        },
        "url": {
            name: "URL",
            cellNode: TableCellOverflowLink
        },
        "webUrl": {
            name: "Web URL",
            cellNode: TableCellOverflowLink
        }
    }

    const getData = useCallback(async () => {
        const url = new URL("/api/v1.0/director_ui/servers", window.location.origin)
        if (type){
            url.searchParams.append("server_type", type)
        }

        let response = await fetch(url)
        if (response.ok) {
            const responseData: Server[] = await response.json()
            responseData.sort((a, b) => a.name.localeCompare(b.name))
            setData(responseData)

        } else {
            setError("Failed to fetch config, response status: " + response.status)
        }
    }, [type])

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
        <Paper
            elevation={2}
            sx={{backgroundColor: "#F6F6F6", borderRadius: "1rem", overflow: "hidden"}}
        >
            {data ? <DataTable columnMap={keyToName} data={data} /> : <Skeleton variant={"rectangular"} height={200} width={"100%"} />}
        </Paper>
    )
}
