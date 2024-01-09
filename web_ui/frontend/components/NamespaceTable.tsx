import {Typography, Box, Button, ButtonProps} from '@mui/material';
import React, {
    useCallback,
    useEffect,
    useState
} from "react";
import {Skeleton} from "@mui/material";

import {Card} from "@/components/Namespace";
import {Namespace} from "@/components/Main";


interface ServerTableProps {
    type?: "cache" | "origin"
}

const NamespaceTable = ({type} : ServerTableProps) => {

    const [data, setData] = useState<Namespace[] | undefined>(undefined);
    const [error, setError] = useState<string | undefined>(undefined);

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
        <Box display={"flex"}>
            {data ? data.map((namespace) => <Card key={namespace.id} namespace={namespace}/>) : <Skeleton variant={"rectangular"} width={"100%"} height={"100%"}/>}
        </Box>
    )
}

export default NamespaceTable
