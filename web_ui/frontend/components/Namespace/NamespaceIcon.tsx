import {Avatar, Box, Tooltip} from "@mui/material";
import {Person, Storage, TripOrigin} from "@mui/icons-material";
import React from "react";
import {Namespace} from "@/components/Main";

const NamespaceIcon = ({ namespace }: { namespace: Namespace }) => {

    if (namespace.type == "origin") {
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

    if (namespace.type == "cache") {
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
