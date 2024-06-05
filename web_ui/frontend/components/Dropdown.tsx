import {Box, BoxProps, Collapse} from "@mui/material";
import React from "react";

interface DropdownProps extends BoxProps {
    transition: boolean;
}

export const Dropdown = ({transition, children, ...props} : DropdownProps) => {

    return (
        <Collapse in={transition}>
            <Box
                sx={{
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: "0px 0px 4px 4px",
                    p: 2,
                    ...props?.sx
                }}
                {...props}
            >
                {children}
            </Box>
        </Collapse>
    )
}

export default Dropdown;
