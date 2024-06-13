import React, {ComponentType, FunctionComponent, useMemo, useState, JSX} from "react";
import {Box, Grid, Pagination, TextField, Typography} from "@mui/material";
import {DirectorCard, DirectorCardProps} from "./";
import {Server} from "@/index";
import {BooleanToggleButton, CardList} from "@/components";
import useFuse from '@/helpers/useFuse';

interface DirectorCardListProps {
    data: Partial<DirectorCardProps>[];
    cardProps: Partial<DirectorCardProps>;
}

export function DirectorCardList({ data, cardProps }: DirectorCardListProps) {

    const [search, setSearch] = useState<string>("")
    const [pelicanServer, setPelicanServer] = useState<boolean | undefined>(undefined)
    const [serverError, setServerError] = useState<boolean | undefined>(undefined)
    const [serverDowntime, setServerDowntime] = useState<boolean | undefined>(undefined)

    const searchedData = useFuse<Partial<DirectorCardProps>>(data, search)

    const filteredData = useMemo(() => {
        let filteredData = structuredClone(searchedData)
        if (pelicanServer != undefined) {
            filteredData = filteredData.filter((d) => d?.server?.fromTopology != pelicanServer)
        }
        if (serverError != undefined) {
            filteredData = filteredData.filter((d) => serverHasError(d?.server) == serverError)
        }
        if (serverDowntime != undefined) {
            filteredData = filteredData.filter((d) => d?.server?.filtered == serverDowntime)
        }
        return filteredData
    }, [searchedData, search, serverError, pelicanServer, serverDowntime])

    return (
        <Box>
            <Box sx={{pb: 1}}>
                <TextField
                    size={"small"}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    label="Search"
                />
                <Grid container spacing={1} pt={1}>
                    <Grid item>
                        <BooleanToggleButton label={"Is Pelican Server"} value={pelicanServer} onChange={setPelicanServer}/>
                    </Grid>
                    <Grid item>
                        <BooleanToggleButton label={"Has Error"} value={serverError} onChange={setServerError} />
                    </Grid>
                    <Grid item>
                        <BooleanToggleButton label={"Is Disabled"} value={serverDowntime} onChange={setServerDowntime} />
                    </Grid>
                </Grid>
            </Box>
            <CardList data={filteredData} Card={DirectorCard} cardProps={cardProps}/>
        </Box>
    )
}

const serverHasError = (server?: Server) => {
    return server?.healthStatus === "Error";
}

export default DirectorCardList;
