import React, {ComponentType, FunctionComponent, useMemo, useState, JSX} from "react";
import {Box, Pagination, TextField} from "@mui/material";

function searchObject<T>(o: T, search: string){
    const objectString = JSON.stringify(o).toLowerCase()
    return objectString.includes(search.toLowerCase())
}

interface CardListProps<T> {
    data: Partial<T>[];
    Card: ComponentType<any>;
    cardProps: Partial<T>;
}

function CardList<T>({ data, Card, cardProps }: CardListProps<T>) {

    const PAGE_SIZE = 5

    const [search, setSearch] = useState<string>("")
    const [page, setPage] = useState<number>(1)

    const filteredObjects = useMemo(() => {
        return data.filter((d) => searchObject<Partial<T>>(d, search))
    }, [data, search])

    const count = useMemo(() => {
        return Math.ceil(filteredObjects.length / PAGE_SIZE)
    }, [filteredObjects])

    const slicedObjects = useMemo(() => {
        return filteredObjects.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
    }, [filteredObjects, page])

    return (
        <Box>
            <Box sx={{pb: 1}}>
                <TextField
                    size={"small"}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    label="Search"
                    color={slicedObjects.length == 0 ? "warning" : "primary"}
                    helperText={slicedObjects.length == 0 ? "No results found" : undefined}
                />
            </Box>
            { slicedObjects.length != 0 &&
                <>
                    <Box>
                        {slicedObjects.map((o, i) => {

                            const props = {
                                ...cardProps,
                                ...o
                            } as T

                            return <Box pb={1} key={JSON.stringify(props)}>
                                <Card {...props} />
                            </Box>
                        })}
                    </Box>
                    {   count > 1 &&
                        <Box display={"flex"} justifyContent={"center"}>
                            <Pagination count={count} page={page} onChange={(e, p) => setPage(p)} />
                        </Box>
                    }
                </>
            }
        </Box>
    )
}

export default CardList;
