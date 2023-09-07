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

import RateGraph from "@/components/graphs/RateGraph";
import LineGraph from "@/components/graphs/LineGraph";

import {Box, Grid} from "@mui/material";
import Image from 'next/image'
import styles from './page.module.css'


export default function Home() {



    return (
        <Box width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={6}>
                    <Box sx={{backgroundColor: "#F6F6F6", borderRadius: "1rem"}} p={2}>
                        <Box minHeight={"200px"}>
                            <RateGraph
                                rate={"10m"}
                                duration={"24h"}
                                resolution={"10m"}
                                metric={"xrootd_monitoring_packets_received"}
                                datasetOptions={{label: "xrootd_monitoring_packets_received rate over 10m", borderColor: "#0071ff"}}
                                boxProps={{
                                    maxHeight:"400px",
                                    flexGrow:1,
                                    justifyContent:"center",
                                    display:"flex"
                                }}
                            />
                        </Box>
                    </Box>
                </Grid>
                <Grid item xs={12} lg={6}>
                    <Box sx={{backgroundColor: "#F6F6F6", borderRadius: "1rem"}} p={2}>
                        <Box minHeight={"200px"}>
                            <LineGraph
                                metric={"xrootd_server_connection_count"}
                                duration={"24h"}
                                resolution={"10m"}
                                datasetOptions={{label: "xrootd_server_connection_count", borderColor: "#0071ff"}}
                                boxProps={{
                                    maxHeight:"400px",
                                    flexGrow:1,
                                    justifyContent:"center",
                                    display:"flex"
                                }}
                            />
                        </Box>
                    </Box>
                </Grid>
            </Grid>

        </Box>
    )
}
