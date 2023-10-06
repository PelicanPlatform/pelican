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

import {Box, Grid, Skeleton, Typography} from "@mui/material";
import {useEffect, useState} from "react";
import {DateTime} from "luxon";
import { alpha, useTheme } from "@mui/material";

interface StatusDisplayProps {
    component: string;
    status: string;
}

function StatusDisplay({component, status}: StatusDisplayProps) {

    const theme = useTheme()

    let backgroundColor = status === "ok" ? theme.palette.success.light : theme.palette.error.light
    let backgroundColorFinal = alpha(backgroundColor, 0.5)

    return (
        <Box p={2} bgcolor={backgroundColorFinal} borderRadius={2} mb={1}>
            <Typography>{`${component}: ${status}`}</Typography>
        </Box>
    )
}


export default function StatusBox() {

    const [status, setStatus] = useState<any>(undefined)
    const [updated, setUpdated] = useState<DateTime>(DateTime.now())

    let getStatus = async () => {
        let response = await fetch("/api/v1.0/health")
        let data = await response.json()
        setUpdated(DateTime.now())
        setStatus(data)
    }

    useEffect(() => {
        getStatus()

        const interval = setInterval(() => getStatus(), 60000);
        return () => clearInterval(interval)
    }, [])

    if(status === undefined){
        return (
            <Box>
                <Typography variant="h4">Status</Typography>
                <Box minHeight={"300px"}>
                    <Skeleton variant="rectangular" height={250} />
                </Box>
            </Box>
        )
    }

    return (
        <Box>
            <Box>
                <Typography variant="h4">Status</Typography>
            </Box>
            <Box>
                <StatusDisplay component={"CMSD"} status={status["components"]["cmsd"]['status']} />
                <StatusDisplay component={"Web UI"} status={status["components"]["web-ui"]['status']} />
                <StatusDisplay component={"XROOTD"} status={status["components"]["xrootd"]['status']} />
            </Box>
            <Box>
                <Typography sx={{color: "grey"}} variant={"subtitle2"}>Last Updated: {updated.toLocaleString(DateTime.DATETIME_MED)}</Typography>
            </Box>
        </Box>
    )
}
