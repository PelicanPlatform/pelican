import {Avatar, Box, Tooltip} from "@mui/material";
import {FolderOpen, Storage, TripOrigin} from "@mui/icons-material";
import React from "react";

const NamespaceIcon = ({ serverType: prefixType }: { serverType: "origin" | "cache" | "namespace"}) => {
    if (prefixType == "namespace") {
        return (
            <Box>
                <Tooltip title={"Namespace"} placement={"left"}>
                    <Avatar sx={{height: "30px", width: "30px", my: "auto", mr: 1, bgcolor: "primary.main"}}>
                        <FolderOpen/>
                    </Avatar>
                </Tooltip>
            </Box>
        )
    }

    if (prefixType == "origin") {
        return (
            <Box>
                <Tooltip title={"Origin"} placement={"left"}>
                    <Avatar sx={{height: "30px", width: "30px", my: "auto", mr: 1, bgcolor: "primary.main"}}>
                        <TripOrigin/>
                    </Avatar>
                </Tooltip>
            </Box>
        )
    }

    if (prefixType == "cache") {
        return (
            <Box>
                <Tooltip title={"Cache"} placement={"left"}>
                    <Avatar sx={{height: "30px", width: "30px", my: "auto", mr: 1, bgcolor: "primary.main"}}>
                        <Storage/>
                    </Avatar>
                </Tooltip>
            </Box>
        )
    }
}

export default NamespaceIcon;
