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

import Image from 'next/image'
import { useRouter } from 'next/navigation'
import {Typography, Box, Button, Snackbar, Alert, Tooltip} from "@mui/material";
import LogoutIcon from '@mui/icons-material/Logout';

import styles from "../../app/page.module.css"
import GithubIcon from "../../public/static/images/github-mark.png"
import React, {ReactNode, useState} from "react";

export const Sidebar = ({children}: {children: ReactNode}) => {
    const router = useRouter()

    const [error, setError] = useState("")

    const handleLogout = async (e: React.MouseEvent<HTMLElement>) => {
        try {
            let response = await fetch("/api/v1.0/auth/logout", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }
            })

            if(response.ok){
                router.push("/")
            } else {
                try {
                    let data = await response.json()
                    if (data?.error) {
                        setError(response.status + ": " + data['error'])
                    } else {
                        setError("Server error with status code " + response.status)
                    }
                } catch {
                    setError("Server error with status code " + response.status)
                }
            }
        } catch {
            setError("Could not connect to server")
        }
    }

    return (
        <Box>
            <Snackbar
                open={error!=""}
                autoHideDuration={6000}
                onClose={() => {setError("")}}
                anchorOrigin={{vertical: "top", horizontal: "center"}}
            >
                <Alert onClose={() => {setError("")}} severity="error" sx={{ width: '100%' }}>
                    {error}
                </Alert>
            </Snackbar>
            <div className={styles.header} style={{display: "flex", flexDirection: "column", justifyContent:"space-between", padding:"1rem", top:0, position:"fixed", zIndex:"1", overflow: "hidden", height: "100vh"}}>
                <div style={{display:"flex", flexDirection: "column"}}>
                    {children}
                </div>
                <Box display={"flex"} flexDirection={"column"} justifyContent={"center"} textAlign={"center"}>
                    <Tooltip title="Logout" placement="right" arrow>
                        <a aria-label='logout' onClick={handleLogout} style={{marginBottom: 10}}>
                            <LogoutIcon/>
                        </a>
                    </Tooltip>
                    <a href={"https://github.com/PelicanPlatform"}>
                        <Image
                            src={GithubIcon}
                            alt={"Github Mark"}
                            width={32}
                            height={32}
                        />
                    </a>
                </Box>
            </div>
        </Box>

    )
}
