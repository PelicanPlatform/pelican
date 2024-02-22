import React, {useEffect, useMemo, useState} from "react";
import {Box, Pagination, TextField} from "@mui/material";

import {OriginCard, CacheCard} from "./index";
import {Namespace} from "@/components/Main";
import {Authenticated} from "@/helpers/login";

const searchNamespace = (namespace: Namespace, search: string) => {
    const namespaceString = JSON.stringify(namespace)
    return namespaceString.includes(search)
}


const CardList = ({ namespaces, authenticated }: { namespaces: Namespace[], authenticated?: Authenticated }) => {

    const [search, setSearch] = useState<string>("")
    const [page, setPage] = useState<number>(1)

    const filteredNamespaces = useMemo(() => {
        return namespaces.filter((namespace) => searchNamespace(namespace, search))
    }, [namespaces, search])

    const isCache = useMemo(() => {
        return filteredNamespaces.some((namespace) => namespace.prefix.startsWith("/cache"))
    }, [namespaces])

    const count = useMemo(() => {
        return Math.ceil(filteredNamespaces.length / 5)
    }, [namespaces])

    const slicedNamespaces = useMemo(() => {
        return filteredNamespaces.slice((page - 1) * 5, page * 5)
    }, [filteredNamespaces, page])

    if (namespaces.length === 0) {
        return null
    }

    return (
        <Box>
            <Box sx={{pb: 1}}>
                <TextField
                    size={"small"}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    label="Search"
                />
            </Box>
            <Box>
                {slicedNamespaces.map((namespace) => {
                    if(isCache){
                        return <CacheCard key={namespace.id} namespace={namespace} authenticated={authenticated} />
                    } else {
                        return <OriginCard key={namespace.id} namespace={namespace} authenticated={authenticated} />
                    }
                })}
            </Box>
            {   count > 1 &&
                <Box display={"flex"} justifyContent={"center"}>
                    <Pagination count={count} page={page} onChange={(e, p) => setPage(p)} />
                </Box>
            }
        </Box>
    )
}

export default CardList;
