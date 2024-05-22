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

'use client'

import {useEffect, useState} from "react";
import {Box, Button, Grid, IconButton, Tooltip, Typography} from "@mui/material";
import {FolderOpen, TripOrigin, Key} from "@mui/icons-material";
import {getErrorMessage} from "@/helpers/util";
import AlertPortal from "./AlertPortal";
import {Alert as AlertType} from "@/components/Main";

const RegisterNamespace = () => {

    const actions = [
      {
          href: "/registry/namespace/register/",
          icon: <FolderOpen/>,
          text: "Namespace",
          title: "Register a new Namespace"
      },
      {
          href: "/registry/origin/register/",
          icon: <TripOrigin/>,
          text: "Origin",
          title: "Register a new Origin"
      }
    ]

    const [registryUrl, setRegistryUrl] = useState<string | undefined>(undefined)
    const [fromUrl, setFromUrl] = useState<string | undefined>(undefined)
    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

    const getRegUrl = async () => {
        const response = await fetch("/api/v1.0/config")
        if(response.ok) {
            const responseData = await response.json()
            let regUrl = responseData?.Federation?.RegistryUrl?.Value
            if(regUrl && !regUrl?.startsWith("http://") && !regUrl?.startsWith("https://")) {
                regUrl = "https://" + regUrl
            }
            setRegistryUrl(regUrl)
        } else {
            console.error(await getErrorMessage(response))
        }
    }

    const handleClick = async (e: React.MouseEvent) => {
        e.stopPropagation()
        const keyResponse = await fetch("/.well-known/issuer.jwks")
        if(keyResponse.ok) {
          const data = await keyResponse.json()
          await navigator.clipboard.writeText(JSON.stringify(data))
          setAlert({severity: "success", message: "Copied public key to the clipboard"})
        } else {
          const errMsg = await getErrorMessage(keyResponse)
          console.error(errMsg)
          setAlert({severity: "error", message: errMsg})
        }
    }

    useEffect(() => {
        const myUrl = window.location.href
        setFromUrl(myUrl)
        getRegUrl()
    }, [])

    if(registryUrl === undefined) {
        return
    }

    return (
        <Box width={"100%"} marginTop={"1em"}>
            <AlertPortal alert={alert} onClose={() => setAlert(undefined)} snackBarProps={{autoHideDuration: 3000}} />
            <Typography variant={"h4"} component={"h2"} mb={2}>Register Namespace</Typography>
            <Grid container spacing={2}>
                {
                    actions.map((action, idx) => {
                      let finalUrl = registryUrl + "/view" + action.href
                      if (fromUrl) {
                        finalUrl = finalUrl + "?fromUrl=" + encodeURIComponent(fromUrl)
                      }
                      return (
                        <Grid item key={idx}>
                          <Tooltip title={action.title}>
                                <Button
                                    href={finalUrl}
                                    rel={"noopener noreferrer"}
                                    target={"_blank"}
                                    variant="outlined"
                                    sx={{bgcolor: "white", "&:hover": {bgcolor: "white"}}}
                                    startIcon={action.icon}>
                                        {action.text}
                                </Button>
                          </Tooltip>
                        </Grid>
                      )
                    })
                }
                <Grid item key={"pubkey"}>
                    <Tooltip title={"Copy Pelican public key"}>
                        <IconButton onClick={handleClick}>
                          <Key/>
                        </IconButton>
                    </Tooltip>
                </Grid>
            </Grid>
        </Box>
    )
}

export default RegisterNamespace;
