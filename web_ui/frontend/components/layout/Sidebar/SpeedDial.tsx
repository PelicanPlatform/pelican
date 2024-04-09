"use client"

import React, {ReactNode, useState} from "react";
import {Box, BoxProps, Button, Grow, IconButton, Paper, Tooltip} from "@mui/material";
import Link from "next/link";
import {BugReport, Description, HelpOutline} from "@mui/icons-material";
import GitHubIcon from "@mui/icons-material/GitHub";
import {ClickAwayListener} from "@mui/base";

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
    const { version } = require('../../../package.json');
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
                            <Link href={href} rel={"noopener noreferrer"} target={"_blank"}>
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
                                        <Button sx={{fontSize: "16px", color: "black"}} href={`https://github.com/PelicanPlatform/pelican/releases/tag/v${getVersionNumber()}`}>
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

export default PelicanSpeedDial;