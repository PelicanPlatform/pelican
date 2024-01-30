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
import {Typography, Box, Button, Snackbar, Alert, Tooltip, IconButton, Grow, Paper, BoxProps} from "@mui/material";
import { ClickAwayListener } from '@mui/base';
import {Help, HelpOutline, Description, BugReport} from "@mui/icons-material";
import LogoutIcon from '@mui/icons-material/Logout';

import styles from "../../app/page.module.css"
import GitHubIcon from '@mui/icons-material/GitHub';
import React, {ReactNode, useState} from "react";
import Link from 'next/link';

interface SpeedButtonProps {
    open: boolean,
    order: number,
    icon: ReactNode,
    title: string,
    onClick?: () => void
    href?: string
    boxProps?: BoxProps
}

export const getVersionNumber = () => {
    const { version } = require('../../package.json');
    return version;
}

const SpeedDialButton = ({open, order, icon, title, onClick, href, boxProps} : SpeedButtonProps) => {

    // Logical XOR
    if((href != undefined) == (onClick != undefined)){
        throw new Error("SpeedDialButton must have either an onClick xor href prop")
    }

    return (
        <Grow
            in={open}
            style={{ transformOrigin: '0 0 0' }}
            {...(open ? { timeout: 200 * order } : {})}
        >
            <Box pl={1} {...boxProps}>
                <Tooltip title={title} arrow>
                    <Paper elevation={2} sx={{ borderRadius: "50%", bgcolor: "#ffffff00"}}>
                        { href != undefined ?
                            <Link href={href}>
                                <IconButton sx={{bgcolor: "primary.light", "&:hover": {bgcolor: "white"}}}>
                                    {icon}
                                </IconButton>
                            </Link>
                            :
                            <IconButton sx={{bgcolor: "primary.light", "&:hover": {bgcolor: "white"}}} onClick={onClick}>
                                {icon}
                            </IconButton>
                        }
                    </Paper>
                </Tooltip>
            </Box>
        </Grow>
    )

}

const PelicanSpeedDial = () => {
    const [open, setOpen] = useState(false);

    const actions = [
        {
            boxProps: {pl: 3},
            icon: <Description/>,
            title: 'Documentation',
            href: "https://docs.pelicanplatform.org"
        },
        {
            icon: <GitHubIcon/>,
            title: 'Github',
            href: "https://github.com/PelicanPlatform/pelican"
        },
        {
            icon: <BugReport/>,
            title: 'Report Bug',
            href: "https://github.com/PelicanPlatform/pelican/issues/new"
        }
    ];

    return (
        <ClickAwayListener onClickAway={() => setOpen(false)}>
            <Box sx={{
                display: "flex",
                flexDirection: "row",
            }}>
                <Paper elevation={open ? 2 : 0} sx={{ borderRadius: "50%", bgcolor: "#ffffff00"}}>
                    <IconButton onClick={() => setOpen(!open)}>
                        <HelpOutline/>
                    </IconButton>
                </Paper>
                <Box position={"relative"}>
                    <Box
                        sx={{
                            position: 'absolute',
                            top: 0,
                            left: 0,
                            display: 'flex',
                            flexDirection: 'row'
                        }}
                    >
                        {actions.map((action, index) => (
                            <SpeedDialButton
                                key={action.title}
                                open={open}
                                order={index}
                                {...action}
                            />
                        ))}
                        <Grow
                            in={open}
                            style={{ transformOrigin: '0 0 0' }}
                            {...(open ? { timeout: 200 * actions.length } : {})}
                        >
                            <Box pl={1}>
                                <Tooltip title={"Active Version"} arrow>
                                    <Paper elevation={2} sx={{ bgcolor: "primary.light", borderRadius: "20px", "&:hover": {bgcolor: "white"}}}>
                                        <Button sx={{fontSize: "16px", color: "black"}} href={"https://github.com/PelicanPlatform/pelican/releases"}>
                                            {getVersionNumber()}
                                        </Button>
                                    </Paper>
                                </Tooltip>
                            </Box>
                        </Grow>
                    </Box>
                </Box>
            </Box>
        </ClickAwayListener>
    )
}




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
            <Box sx={{
                display: "flex",
                flexDirection: "row",
                top:0,
                position:"fixed",
                zIndex:2
            }}>
                <Box height={"100vh"} display={"flex"}>
                    <Box className={styles.header} style={{display: "flex", flexDirection: "column", justifyContent:"space-between", padding:"1rem", flexGrow: 1}}>
                        <Box style={{display:"flex", flexDirection: "column"}}>
                            {children}
                        </Box>
                        <Box display={"flex"} flexDirection={"column"} justifyContent={"center"} textAlign={"center"}>
                            <Tooltip title="Logout" placement="right" arrow>
                                <IconButton aria-label='logout' onClick={handleLogout} style={{marginBottom: 10}}>
                                    <LogoutIcon/>
                                </IconButton>
                            </Tooltip>
                            <PelicanSpeedDial/>
                        </Box>
                    </Box>
                </Box>
            </Box>
        </Box>

    )
}
