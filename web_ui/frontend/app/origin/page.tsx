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

import {Box, Grid, Typography} from "@mui/material";

import RateGraph from "@/components/graphs/RateGraph";
import StatusBox from "@/components/StatusBox";
import {DataExportTable} from "@/components/DataExportTable";
import {TimeDuration} from "@/components/graphs/prometheus";
import FederationOverview from "@/components/FederationOverview";

export default function Home() {

    return (
        <Box width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={4}>
                    <Typography variant="h4">Status</Typography>
                    <StatusBox/>
                </Grid>
                <Grid item xs={12} lg={8}>
                    <Box sx={{backgroundColor: "#F6F6F6", borderRadius: "1rem"}} p={2}>
                        <Box minHeight={"200px"}>
                            <RateGraph
                                rate={TimeDuration.fromString("3h")}
                                duration={TimeDuration.fromString("7d")}
                                resolution={TimeDuration.fromString("3h")}
                                metrics={['xrootd_server_bytes{direction="rx"}', 'xrootd_server_bytes{direction="tx"}']}
                                boxProps={{
                                    maxHeight:"400px",
                                    flexGrow:1,
                                    justifyContent:"center",
                                    display:"flex"
                                }}
                                options={{
                                    scales: {
                                        x: {
                                            type: 'time',
                                            time: {
                                                round: 'second',
                                            }
                                        }
                                    },
                                    plugins: {
                                        zoom: {
                                            zoom: {
                                                drag: {
                                                    enabled: true,
                                                },
                                                mode: 'x',
                                                // TODO - Implement smart update on zoom: onZoom: (chart) => console.log(chart)
                                            },
                                        },
                                    },
                                }}
                                datasetOptions={[
                                    {label: "xrootd_server_bytes{direction=\"rx\"}", borderColor: "#0071ff"},
                                    {label: "xrootd_server_bytes{direction=\"tx\"}", borderColor: "#54ff80"}
                                ]}
                            />
                        </Box>
                    </Box>
                </Grid>
                <Grid item xs={12} lg={4}>
                    <Typography variant={"h4"} component={"h2"} mb={2}>Data Exports</Typography>
                    <Box sx={{backgroundColor: "#F6F6F6", borderRadius: "1rem", overflow: "hidden"}}>
                        <DataExportTable/>
                    </Box>
                </Grid>
                <Grid item xs={12} lg={4}>
                    <FederationOverview/>
                </Grid>
            </Grid>

        </Box>
    )
}
