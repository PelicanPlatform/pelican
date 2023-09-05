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
                        <Box display={"flex"}  minHeight={"200px"} maxHeight={"400px"} m={"auto"} flexGrow={1} justifyContent={"center"}>
                            <RateGraph
                                rate={"10m"}
                                duration={"24h"}
                                resolution={"10m"}
                                metric={"xrootd_monitoring_packets_received"}
                                datasetOptions={{label: "xrootd_monitoring_packets_received rate over 10m", borderColor: "#0071ff"}}
                            />
                        </Box>
                    </Box>
                </Grid>
                <Grid item xs={12} lg={6}>
                    <Box sx={{backgroundColor: "#F6F6F6", borderRadius: "1rem"}} p={2}>
                        <Box display={"flex"} minHeight={"200px"} maxHeight={"400px"} flexGrow={1} justifyContent={"center"}>
                            <LineGraph
                                metric={"xrootd_server_connection_count"}
                                duration={"24h"}
                                resolution={"10m"}
                                datasetOptions={{label: "xrootd_server_connection_count", borderColor: "#0071ff"}}
                            />
                        </Box>
                    </Box>
                </Grid>
            </Grid>

        </Box>
    )
}
