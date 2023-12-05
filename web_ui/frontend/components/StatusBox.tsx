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
    message?: string;
}

function StatusDisplay({component, status, message}: StatusDisplayProps) {

    const theme = useTheme()

    let backgroundColor: string
    switch (status) {
        case "ok":
            backgroundColor = theme.palette.success.light
            break
        case "warning":
            backgroundColor = theme.palette.warning.light
            break
        case "critical":
            backgroundColor = theme.palette.error.light
            break
        default:
            backgroundColor = theme.palette.warning.light
    }

    let backgroundColorFinal = alpha(backgroundColor, 0.5)

    switch (component) {
        case "xrootd":
            component = "XRootD"
            break
        case "web-ui":
            component = "Web UI"
            break
        case "cmsd":
            component = "CMSD"
            break
        case "federation":
            component = "Federation"
            break
        case "director":
            component = "Director"
            break
        default:
    }

    return (
        <Box p={1} px={2} display={"flex"} flexDirection={"column"} bgcolor={backgroundColorFinal} borderRadius={2} mb={1}>
            <Box>
                <Typography>
                    {component}
                </Typography>
            </Box>
            { message ?
                <Box>
                    <Typography variant={"body2"}>
                        {message}
                    </Typography>
                </Box> :
                undefined
            }
        </Box>
    )
}


export default function StatusBox() {

    const [status, setStatus] = useState<any>(undefined)
    const [updated, setUpdated] = useState<DateTime>(DateTime.now())
    const [error, setError] = useState<string | undefined>(undefined)

    let getStatus = async () => {
        let response = await fetch("/api/v1.0/health")

        if(response.ok) {
            let data = await response.json()
            setUpdated(DateTime.now())
            setStatus(data)
        } else {
            setError("Error fetching status json: " + response.status)
        }

    }

    useEffect(() => {
        getStatus()

        const interval = setInterval(() => getStatus(), 60000);
        return () => clearInterval(interval)
    }, [])

    if(status === undefined || error !== undefined) {
        return (
            <Box>
                <Typography variant="h4">Status</Typography>
                <Box minHeight={"300px"}>
                    {
                        error ?
                            <Typography sx={{color: "red"}} variant={"subtitle2"}>{error}</Typography> :
                            <Skeleton variant="rectangular" height={250} />
                    }
                </Box>
            </Box>
        )
    }

    let statusComponents: any[] = []
    try {
        statusComponents = Object.entries(status['components']).map(([component, status]: [string, any]) => {
            return (
                <StatusDisplay key={component} component={component} status={status['status']} message={status['message']}/>
            )
        })
    } catch (e) {
        setError("Error parsing status json: " + e)
    }




    return (
        <Box>
            <Box>
                <Typography variant="h4">Status</Typography>
            </Box>
            <Box>
                {statusComponents}
            </Box>
            <Box>
                <Typography sx={{color: "grey"}} variant={"subtitle2"}>Last Updated: {updated.toLocaleString(DateTime.DATETIME_MED)}</Typography>
            </Box>
        </Box>
    )
}
