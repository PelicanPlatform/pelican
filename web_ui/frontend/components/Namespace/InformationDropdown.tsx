import {Box, Tooltip, Collapse, Grid, Typography} from "@mui/material";
import React from "react";
import {NamespaceAdminMetadata} from "./index.d";

const InformationSpan = ({name, value}: {name: string, value: string}) => {
    return (
        <Tooltip title={name} placement={"right"}>
            <Box sx={{
                "&:nth-of-type(odd)": {
                    bgcolor: "#ececec",
                    p: "4px 6px",
                    m: "0px -5px",
                    borderRadius: "4px"
                },
                "&:nth-of-type(even)": {
                    p: "4px 6px",
                    m: "0px -5px"
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

interface InformationDropdownProps {
    adminMetadata: NamespaceAdminMetadata;
    transition: boolean;
    parentRef?: React.RefObject<HTMLDivElement>;
}

const InformationDropdown = ({adminMetadata, transition, parentRef} : InformationDropdownProps) => {

    const approvedAt = adminMetadata.approved_at == "0001-01-01T00:00:00Z" ?
        "" : new Date(Date.parse(adminMetadata.approved_at)).toLocaleString()

    const information = [
        {name: "User ID", value: adminMetadata.user_id},
        {name: "Description", value: adminMetadata.description},
        {name: "Site Name", value: adminMetadata.site_name},
        {name: "Institution", value: adminMetadata.institution},
        {name: "Security Contact User ID", value: adminMetadata.security_contact_user_id},
        {name: "Status", value: adminMetadata.status},
        {name: "Approver ID", value: adminMetadata.approver_id.toString()},
        {name: "Approved At", value: approvedAt},
        {name: "Created At", value: new Date(Date.parse(adminMetadata.created_at)).toLocaleString()},
        {name: "Updated At", value: new Date(Date.parse(adminMetadata.updated_at)).toLocaleString()}
    ]

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
                }}
            >
                <Grid container>
                    <Grid item xs={12}>
                        <Box>
                            {information.map((info) => <InformationSpan key={info.name} {...info}/>)}
                        </Box>
                    </Grid>
                </Grid>
            </Box>
        </Collapse>
    )
}

export default InformationDropdown;
