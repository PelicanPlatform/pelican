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
import {TableCellOverflow} from "@/components/Cell";
import Link from "next/link";

interface ColumnMap {
    [key: string]: Column
}

interface Column {
    name: string
    cellNode: React.JSX.ElementType
}

interface Record {
    [key: string]: string | number | boolean | null
}

interface ExportData extends Record {
    "Type": string
    "Local Path": string
    "Namespace Prefix": string
}

const TableCellOverflowLink: React.JSX.ElementType = ({ children, ...props }) => {
    return (
        <TableCellOverflow sx={{color: "blue", cursor: "pointer"}} {...props}>
            <Link href={children as string}>
                {children as string}
            </Link>
        </TableCellOverflow>
    )
}

export const DataTable = ({ columnMap, data }: { columnMap: ColumnMap, data: Record[] }): ReactElement  => {

    return (
        <TableContainer sx={{maxHeight: "500px"}}>
            <Table stickyHeader={true} sx={{tableLayout: "fixed"}}>
                <TableHead>
                    <TableRow>
                        {Object.values(columnMap).map((column, index) => (
                            <TableCell key={index}>{column.name}</TableCell>
                        ))}
                    </TableRow>
                </TableHead>
                <TableBody>
                    {data.map((record, index) => (
                        <TableRow key={index}>
                            {Object.entries(columnMap).map(([key, column], index) => {
                                const CellNode = column.cellNode
                                return <CellNode key={index}>{record[key] == null ? "NULL" : record[key]}</CellNode>
                            })}
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
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
        }
        // webUrl: "Web URL"  TODO: Uncomment when the Web URL is populated someday - Cannon Lock 2023/12/06
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
        <>
            {data ? <DataTable columnMap={keyToName} data={data} /> : <Skeleton variant={"rectangular"} height={200} width={"100%"} />}
        </>
    )
}
