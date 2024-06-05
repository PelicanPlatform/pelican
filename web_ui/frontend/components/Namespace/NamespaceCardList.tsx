import React, {ComponentType, FunctionComponent, useMemo, useState, JSX} from "react";
import {Box, Pagination, TextField, Typography} from "@mui/material";

import {CardList} from "@/components";

function searchObject<T>(o: T, search: string){
    const objectString = JSON.stringify(o).toLowerCase()
    return objectString.includes(search.toLowerCase())
}

interface CardListProps<T> {
    data: Partial<T>[];
    Card: ComponentType<any>;
    cardProps: Partial<T>;
}

function NamespaceCardList<T>({ data, Card, cardProps }: CardListProps<T>) {

    const [search, setSearch] = useState<string>("")

    const filteredObjects = useMemo(() => {
        return data.filter((d) => searchObject<Partial<T>>(d, search))
    }, [data, search])

    return (
        <Box>
            <Box sx={{pb: 1}}>
                <TextField
                    size={"small"}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    label="Search"
                    color={filteredObjects.length == 0 ? "warning" : "primary"}
                    helperText={filteredObjects.length == 0 ? "No results found" : undefined}
                />
            </Box>
            <CardList<T> Card={Card} cardProps={cardProps} data={filteredObjects} />
        </Box>
    )
}

export default NamespaceCardList;
