
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

import { getErrorMessage } from "@/helpers/util";
import { Box, Button, Paper, Skeleton, Tooltip, Typography } from "@mui/material";
import {CheckCircle, Warning} from "@mui/icons-material";

import { MouseEventHandler, ReactElement } from "react";
import useSWR from "swr";
import { ValueLabel } from "./DataExportTable";

interface GlobusCollection {
  uuid: string;
  displayName: string;
  federationPrefix: string;
  status: "Activated" | "Inactive";
  description: undefined | string
  httpsServer: string
}

const getGlobusExports = async () : Promise<GlobusCollection[]> => {
  let response = await fetch("/api/v1.0/origin_ui/globus/exports")
  if (response.ok) {
      const responseData = await response.json()
      return responseData
  } else {
      throw new Error(await getErrorMessage(response))
  }
}

const activateBaseUrl = "/api/v1.0/origin_ui/globus/auth/login"

const GlobusRecord = ({data}: {data: GlobusCollection}): ReactElement => {
  return (
    <Paper elevation={3} sx={{mb: 2, pr: "1em", minWidth: 600}}>
      <Box display={"flex"} alignItems={"center"}>
        <Box display={"flex"} alignItems={"flex-start"} justifyContent={"space-between"} flexGrow={1}>
          <ValueLabel label="Federation Prefix" value={data.federationPrefix}/>
          <ValueLabel label="Globus Collection Name" value={data.displayName}/>
        </Box>
        <Box ml={4}>
          {data.status === "Activated" ?
            <Tooltip title="The collection is activated and it's ready to serve files">
              <Button color="success" startIcon={<CheckCircle />}>
                Activated
              </Button>
            </Tooltip>
            :
            <Tooltip title="You need to activate the collection before Pelican can serve the file from this collection">
              <Button
                color={"warning"}
                variant="contained"
                startIcon={<Warning/>}
                onClick={() => {
                  const redirectURL = activateBaseUrl + "/" + data.uuid
                  window.location.href = redirectURL
                }}
                >Activate</Button>
            </Tooltip>
          }
        </Box>
      </Box>

      <Box mt={2}>
        <ValueLabel label="Globus Collection UUID" value={data.uuid}/>
        <ValueLabel label="Https Server" value={data.httpsServer}/>
      </Box>
    </Paper>
  )
}

export const GlobusExportTable = () => {
  const {data, error} = useSWR("getGlobusExport", getGlobusExports)

  if(error){
    return (
        <Box p={1}>
            <Typography sx={{color: "red"}} variant={"subtitle2"}>{error.toString()}</Typography>
        </Box>
    )
  }

  return (
    <Box>
      {data ? data.map((collection) => (<GlobusRecord data={collection} key={collection.uuid}/>))
      :
      <Skeleton variant={"rectangular"} height={200} width={"100%"} />
    }
    </Box>
  )

}
