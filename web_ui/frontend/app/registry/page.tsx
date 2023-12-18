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

import RateGraph from "@/components/graphs/RateGraph";
import StatusBox from "@/components/StatusBox";

import {TimeDuration} from "@/components/graphs/prometheus";

import {Box, Grid, Typography} from "@mui/material";
import FederationOverview from "@/components/FederationOverview";
import {ServerTable} from "@/components/ServerTable";
import NamespaceTable from "@/components/NamespaceTable";


export default function Home() {

    return (
        <Box width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={6}>
                    <Typography variant={"h4"}>Origins</Typography>
                    <NamespaceTable type={"origin"}/>
                </Grid>
                <Grid item xs={12} lg={6}>
                    <Typography variant={"h4"} >Caches</Typography>
                    <NamespaceTable type={"cache"}/>
                </Grid>
            </Grid>
        </Box>
    )
}
