import {Box, Tooltip, Typography} from "@mui/material";
import React from "react";

export const InformationSpan = ({name, value}: {name: string, value: string}) => {
    return (
        <Tooltip title={name} placement={"right"}>
            <Box sx={{
                "&:nth-of-type(odd)": {
                    bgcolor: "#ececec",
                    p: "4px 6px",
                    borderRadius: "4px"
                },
                "&:nth-of-type(even)": {
                    p: "4px 6px",
                },
                display: "flex",
                justifyContent: "space-between",
            }}>
                <Typography variant={"body2"} sx={{fontWeight: 500,  display: "inline", mr: 2}}>{name}</Typography>
                <Typography variant={"body2"} sx={{display: "inline"}}>{value}</Typography>
            </Box>
        </Tooltip>
    )
}

export default InformationSpan;
