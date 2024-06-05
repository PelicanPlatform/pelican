import React, {ComponentType, FunctionComponent, useMemo, useState, JSX} from "react";
import {Box, Grid, Pagination, TextField, Typography} from "@mui/material";
import {DirectorCard, DirectorCardProps} from "./";
import {Server} from "@/index";
import {BooleanToggleButton, CardList} from "@/components";

function searchObject<T>(o: T, search: string){
    const objectString = JSON.stringify(o).toLowerCase()
    return objectString.includes(search.toLowerCase())
}

interface DirectorCardListProps {
    data: Partial<DirectorCardProps>[];
    cardProps: Partial<DirectorCardProps>;
}

export function DirectorCardList({ data, cardProps }: DirectorCardListProps) {

    const [search, setSearch] = useState<string>("")
    const [pelicanServer, setPelicanServer] = useState<boolean | undefined>(undefined)
    const [serverError, setServerError] = useState<boolean | undefined>(undefined)
    const [serverDowntime, setServerDowntime] = useState<boolean | undefined>(undefined)

    const filteredData = useMemo(() => {
        let filteredData = structuredClone(data)
        filteredData = data.filter((d) => searchObject<Partial<DirectorCardProps>>(d, search))
        if (pelicanServer != undefined) {
            filteredData = filteredData.filter((d) => isPelicanServer(d?.server) == pelicanServer)
        }
        if (serverError != undefined) {
            filteredData = filteredData.filter((d) => serverHasError(d?.server) == serverError)
        }
        if (serverDowntime != undefined) {
            filteredData = filteredData.filter((d) => d?.server?.filtered == serverDowntime)
        }
        return filteredData
    }, [data, search, serverError, pelicanServer, serverDowntime])

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
                        <BooleanToggleButton label={"Pelican Server"} value={pelicanServer} onChange={setPelicanServer}/>
                    </Grid>
                    <Grid item>
                        <BooleanToggleButton label={"Error"} value={serverError} onChange={setServerError} />
                    </Grid>
                    <Grid item>
                        <BooleanToggleButton label={"Down"} value={serverDowntime} onChange={setServerDowntime} />
                    </Grid>
                </Grid>
            </Box>
            <CardList data={filteredData} Card={DirectorCard} cardProps={cardProps}/>
        </Box>
    )
}

const isPelicanServer = (server?: Server) => {
    return server?.webUrl != "";
}

const serverHasError = (server?: Server) => {
    return server?.status == "Error";
}

export default DirectorCardList;
