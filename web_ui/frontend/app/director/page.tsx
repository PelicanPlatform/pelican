/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

"use client"


import {Box, Grid, Skeleton, Typography} from "@mui/material";
import {useEffect, useMemo, useState} from "react";
import useSWR from "swr";
import {Server} from "@/components/Main";
import CardList from "@/components/Namespace/CardList";
import DirectorCard, {DirectorCardProps} from "@/components/Namespace/DirectorCard";
import {Authenticated, getAuthenticated, isLoggedIn} from "@/helpers/login";
import FederationOverview from "@/components/FederationOverview";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";


const getServers = async () => {
    const url = new URL("/api/v1.0/director_ui/servers", window.location.origin)

    let response = await fetch(url)
    if (response.ok) {
        const responseData: Server[] = await response.json()
        responseData.sort((a, b) => a.name.localeCompare(b.name))
        return responseData
    }

    throw new Error("Failed to fetch servers")
}

export default function Home() {

    const [error, setError] = useState<string | undefined>(undefined);
    const [authenticated, setAuthenticated] = useState<Authenticated | undefined>(undefined)

    const {data} = useSWR<Server[]>("getServers", getServers)

    useEffect(() => {
        (async () => {
            if(await isLoggedIn()){
                setAuthenticated(getAuthenticated() as Authenticated)
            }
        })();
    }, [])

    const cacheData = useMemo(() => {
        return data?.filter((server) => server.type === "Cache")
    }, [data])

    const originData = useMemo(() => {
        return data?.filter((server) => server.type === "Origin")
    }, [data])

    return (
        <Box width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={8} xl={6}>
                    <Typography variant={"h4"} pb={2}>Origins</Typography>
                    {originData ?
                        <CardList<DirectorCardProps> Card={DirectorCard} cardProps={{authenticated: authenticated}} data={originData.map(x => {return {server: x}})}/> :
                        <Box>
                            <Skeleton variant="rectangular" height={118} />
                        </Box>
                    }
                </Grid>
                <Grid item xs={12} lg={8} xl={6}>
                    <Typography variant={"h4"} pb={2}>Caches</Typography>
                    {cacheData ?
                        <CardList<DirectorCardProps> Card={DirectorCard} cardProps={{authenticated: authenticated}} data={cacheData.map(x => {return {server: x}})}/> :
                        <Box>
                            <Skeleton variant="rectangular" height={118} />
                        </Box>
                    }
                </Grid>
                <AuthenticatedContent>
                    <Grid item xs={12} lg={6}>
                        <FederationOverview/>
                    </Grid>
                </AuthenticatedContent>
            </Grid>
        </Box>
    )
}
