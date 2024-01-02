import {Typography, Box, Button, ButtonProps} from '@mui/material';
import React, {
    useCallback,
    useEffect,
    useState
} from "react";
import {Skeleton} from "@mui/material";

import DataTable, {Record} from "@/components/DataTable";
import {TableCellOverflow, TableCellButton} from "@/components/Cell";


interface Namespace extends Record {
    id: number
    prefix: string
    pubKey: string
    identity: string
    adminMetadata: string
}


interface ServerTableProps {
    type?: "cache" | "origin"
}

const NamespaceTable = ({type} : ServerTableProps) => {

    const [data, setData] = useState<Namespace[] | undefined>(undefined);
    const [error, setError] = useState<string | undefined>(undefined);

    const keyToName = {
        "prefix": {
            name: "Prefix",
            cellNode: TableCellOverflow
        },
        "identity": {
            name: "Identity",
            cellNode: TableCellOverflow
        },
        "admin_metadata": {
            name: "Admin Metadata",
            cellNode: TableCellOverflow
        },
        "id": {
            name: "JWK Download",
            cellNode: ({children} : {children: number}) => <TableCellButton color={"primary"} href={`/api/v1.0/registry_ui/namespaces/${children}/pubkey`}>Download</TableCellButton>
        }
    }

    const getData = useCallback(async () => {
        const url = new URL("/api/v1.0/registry_ui/namespaces", window.location.origin)
        if (type){
            url.searchParams.append("server_type", type)
        }

        let response = await fetch(url)
        if (response.ok) {
            const responseData: Namespace[] = await response.json()
            responseData.sort((a, b) => a.id > b.id ? 1 : -1)
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

export default NamespaceTable
