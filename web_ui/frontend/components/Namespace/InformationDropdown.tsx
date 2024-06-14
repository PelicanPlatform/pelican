import {Box, Tooltip, Collapse, Grid, Typography} from "@mui/material";
import React from "react";
import {NamespaceAdminMetadata} from "./index.d";
import {Dropdown, InformationSpan} from "@/components";

interface InformationDropdownProps {
    adminMetadata: NamespaceAdminMetadata;
    transition: boolean;
    parentRef?: React.RefObject<HTMLDivElement>;
}

const InformationDropdown = ({adminMetadata, transition} : InformationDropdownProps) => {

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
        <Dropdown transition={transition}>
            <Box>
                {information.map((info) => <InformationSpan key={info.name} {...info}/>)}
            </Box>
        </Dropdown>
    )
}

export default InformationDropdown;
