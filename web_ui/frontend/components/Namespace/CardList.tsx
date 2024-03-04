import React, {ComponentType, useEffect, useMemo, useState} from "react";
import {Box, Pagination, TextField} from "@mui/material";

import {Namespace} from "@/components/Main";
import {NamespaceCardProps} from "@/components/Namespace/index.d";
import {PendingCardProps} from "@/components/Namespace/PendingCard";
import card, {CardProps} from "@/components/Namespace/Card";

const searchNamespace = (namespace: Namespace, search: string) => {
    const namespaceString = JSON.stringify(namespace)
    return namespaceString.includes(search)
}

interface CardListProps<T extends PendingCardProps | CardProps> {
    namespaces: Namespace[];
    Card: ComponentType<T>;
    cardProps: Omit<T, "namespace">;
}

function CardList<T extends PendingCardProps | CardProps>({ namespaces, Card, cardProps }: CardListProps<T>) {

    const PAGE_SIZE = 5

    const [search, setSearch] = useState<string>("")
    const [page, setPage] = useState<number>(1)

    const filteredNamespaces = useMemo(() => {
        return namespaces.filter((namespace) => searchNamespace(namespace, search))
    }, [namespaces, search])

    const count = useMemo(() => {
        return Math.ceil(filteredNamespaces.length / PAGE_SIZE)
    }, [namespaces])

    const slicedNamespaces = useMemo(() => {
        return filteredNamespaces.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
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

                    const props = {
                        namespace: namespace,
                        ...cardProps
                    } as T

                    return <Box pb={1} key={namespace.id}>
                        <Card {...props} />
                    </Box>
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
