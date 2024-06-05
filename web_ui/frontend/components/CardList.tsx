import React, {ComponentType, FunctionComponent, useMemo, useState, JSX} from "react";
import {Box, Pagination, Skeleton, TextField, Typography} from "@mui/material";

interface CardListProps<T> {
    data?: Partial<T>[];
    Card: ComponentType<any>;
    cardProps: Partial<T>;
}

export function CardList<T>({ data, Card, cardProps }: CardListProps<T>) {

    const PAGE_SIZE = 5
    const [page, setPage] = useState<number>(1)

    const count = useMemo(() => {
        return Math.ceil((data?.length || 0) / PAGE_SIZE)
    }, [data])

    const slicedObjects = useMemo(() => {
        return (data || []).slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
    }, [data, page])

    return (
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
                {!data || count == 0 && <Skeleton variant="rectangular" height={60}></Skeleton>}
            </Box>
            <Box display={"flex"} justifyContent={"center"} flexDirection={"column"} alignItems={"center"}>
                { count > 1 && <Pagination count={count} page={page} onChange={(e, p) => setPage(p)} /> }
                <Typography variant={"subtitle1"}>{count} items</Typography>
            </Box>
        </>
    )
}

export default CardList;
