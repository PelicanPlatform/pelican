/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

import {Box, Grid, Typography} from "@mui/material";

import RateGraph from "@/components/graphs/RateGraph";
import StatusBox from "@/components/StatusBox";
import {DataExportTable} from "@/components/DataExportTable";
import {TimeDuration} from "@/components/graphs/prometheus";
import FederationOverview from "@/components/FederationOverview";
import {User} from "@/index";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";

export default function Home() {
    return (
        <AuthenticatedContent redirect={true} checkAuthentication={(u: User) => u?.role == "admin"}>
            <Box width={"100%"}>
                <Typography variant="h4" mb={2}>Globus Exports</Typography>
                <Grid container spacing={2}>

                </Grid>
            </Box>
        </AuthenticatedContent>
    )
}
