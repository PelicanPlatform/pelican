import {Box, Typography, Collapse, Grid, IconButton, Button, Tooltip, Skeleton, BoxProps, Avatar} from "@mui/material";
import {Edit, Block, Check, Download, Add, Person} from "@mui/icons-material";
import React, {useEffect, useRef, useState} from "react";
import Link from "next/link";

import {Namespace, Alert} from "@/components/Main";
import {getAuthenticated, secureFetch, Authenticated} from "@/helpers/login";

export interface NamespaceAdminMetadata {
    user_id: string;
    description: string;
    site_name: string;
    institution: string;
    security_contact_user_id: string;
    status: "Pending" | "Approved" | "Denied" | "Unknown";
    approver_id: number;
    approved_at: string;
    created_at: string;
    updated_at: string;
}

interface InformationDropdownProps {
    adminMetadata: NamespaceAdminMetadata;
    transition: boolean;
    parentRef?: React.RefObject<HTMLDivElement>;
}

export const getServerType = (namespace: Namespace) => {

    // If the namespace is empty the value is undefined
    if (namespace?.prefix == null || namespace.prefix == ""){
        return ""
    }

    // If the namespace prefix starts with /cache, it is a cache server
    if (namespace.prefix.startsWith("/cache")) {
        return "cache"
    }

    // Otherwise it is an origin server
    return "origin"

}

const InformationSpan = ({name, value}: {name: string, value: string}) => {
    return (
        <Box sx={{
            "&:nth-of-type(odd)": {
                bgcolor: "#ececec",
                p: "0px 5px",
                m: "0px -5px",
                borderRadius: "4px"
            }
        }}>
            <Typography variant={"body2"} sx={{fontWeight: 500, display: "inline"}}>{name}: </Typography>
            <Typography variant={"body2"} sx={{display: "inline"}}>{value}</Typography>
        </Box>
    )
}

const InformationDropdown = ({adminMetadata, transition, parentRef} : InformationDropdownProps) => {

    const information = [
        {name: "User ID", value: adminMetadata.user_id},
        {name: "Description", value: adminMetadata.description},
        {name: "Site Name", value: adminMetadata.site_name},
        {name: "Institution", value: adminMetadata.institution},
        {name: "Security Contact User ID", value: adminMetadata.security_contact_user_id},
        {name: "Status", value: adminMetadata.status},
        {name: "Approver ID", value: adminMetadata.approver_id.toString()},
        {name: "Approved At", value: adminMetadata.approved_at},
        {name: "Created At", value: adminMetadata.created_at},
        {name: "Updated At", value: adminMetadata.updated_at}
    ]

    return (
        <Collapse in={transition}>
            <Box
                sx={{
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: "0px 0px 10px 10px",
                    p: 1
                }}
            >
                <Grid container>
                    <Grid item>
                        <Box>
                            {information.map((info) => <InformationSpan key={info.name} {...info}/>)}
                        </Box>
                    </Grid>
                </Grid>
            </Box>
        </Collapse>
    )
}

export const CreateNamespaceCard = ({text}: {text: string}) => {
    return (
        <Box>
            <Box
                sx={{
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: 2,
                    p: 1
                }}
                 bgcolor={"secondary"}
            >
                <Box my={"auto"} ml={1}>
                    <Typography>{text ? text : "Register Namespace"}</Typography>
                </Box>
                <Box>
                    <Tooltip title={"Register Namespace"}>
                        <Link href={`/registry/namespace/register`}>
                            <IconButton sx={{bgcolor: "#2e7d3224"}} onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                                <Add/>
                            </IconButton>
                        </Link>
                    </Tooltip>
                </Box>
            </Box>
        </Box>
    )
}

export const Card = ({
    namespace,
    authenticated
} : {namespace: Namespace, authenticated?: Authenticated}) => {
    const ref = useRef<HTMLDivElement>(null);
    const [transition, setTransition] = useState<boolean>(false);

    return (
        <Box>
            <Box
                sx={{
                    cursor: "pointer",
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: transition ? "10px 10px 0px 0px" : 1,
                    "&:hover": {
                        bgcolor: "#ececec"
                    },
                    p: 1
                }}
                bgcolor={"secondary"}
                onClick={() => setTransition(!transition)}
            >
                <Box my={"auto"} ml={1} display={"flex"} flexDirection={"row"}>
                    <Typography>{namespace.prefix}</Typography>
                    { authenticated !== undefined && authenticated.user == namespace.admin_metadata.user_id &&
                        <Tooltip title={"Created By You"}>
                            <Avatar sx={{height: "25px", width: "25px", my: "auto", ml:1}}>
                                <Person/>
                            </Avatar>
                        </Tooltip>
                    }
                </Box>
                <Box>
                    <Tooltip title={"Download JWK"}>
                        <Link href={`https://localhost:8444/api/v1.0/registry_ui/namespaces/${namespace.id}/pubkey`}>
                            <IconButton onClick={(e: React.MouseEvent) => e.stopPropagation()} sx={{mx: 1}}>
                                <Download/>
                            </IconButton>
                        </Link>
                    </Tooltip>
                    {
                        authenticated?.role == "admin" &&
                        <Tooltip title={"Edit Registration"}>
                            <Link href={`/registry/namespace/edit?id=${namespace.id}`}>
                                <IconButton onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                                    <Edit/>
                                </IconButton>
                            </Link>
                        </Tooltip>
                    }
                </Box>
            </Box>
            <Box ref={ref}>
                <InformationDropdown adminMetadata={namespace.admin_metadata} transition={transition} parentRef={ref}/>
            </Box>
        </Box>
    )
}

export const NamespaceCardSkeleton = () => {
    return <Skeleton variant="rounded" width={"100%"} height={60} />
}

interface PendingCardProps {
    namespace: Namespace;
    onUpdate: () => void;
    onAlert: (alert: Alert) => void;
    authenticated?: Authenticated
}

export const PendingCard = ({
    namespace,
    onUpdate,
    onAlert,
    authenticated
}: PendingCardProps) => {

    const ref = useRef<HTMLDivElement>(null);
    const [transition, setTransition] = useState<boolean>(false);

    const approveNamespace = async (e: React.MouseEvent) => {
        try {
            const response = await secureFetch(`/api/v1.0/registry_ui/namespaces/${namespace.id}/approve`, {
                method: "PATCH"
            })

            if (!response.ok){
                onAlert({severity: "error", message: `Failed to approve namespace: ${namespace.prefix}`})
            } else {
                onUpdate()
                onAlert({severity: "success", message: `Successfully approved namespace: ${namespace.prefix}`})
            }

        } catch (error) {
            console.error(error)
        } finally {
            e.stopPropagation()
        }
    }

    const denyNamespace = async (e: React.MouseEvent) => {
        try {
            const response = await secureFetch(`/api/v1.0/registry_ui/namespaces/${namespace.id}/deny`, {
                method: "PATCH"
            })

            if (!response.ok){
                onAlert({severity: "error", message: `Failed to deny namespace: ${namespace.prefix}`})
            } else {
                onUpdate()
                onAlert({severity: "success", message: `Successfully denied namespace: ${namespace.prefix}`})
            }

        } catch (error) {
            console.error(error)
        } finally {
            e.stopPropagation()
        }
    }

    return (
        <Box>
            <Box sx={{
                    cursor: "pointer",
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: transition ? "10px 10px 0px 0px" : 2,
                    "&:hover": {
                        bgcolor: "#ececec"
                    },
                    p: 1
                }}
                bgcolor={"secondary"}
                onClick={() => setTransition(!transition)}
            >
                <Box my={"auto"} ml={1}>
                    <Typography>{namespace.prefix}</Typography>
                </Box>
                <Box>
                    { authenticated?.role == "admin" &&
                        <>
                            <Tooltip title={"Deny Registration"}>
                                <IconButton sx={{bgcolor: "#ff00001a", mx: 1}} color={"error"} onClick={(e) => denyNamespace(e)}><Block/></IconButton>
                            </Tooltip>
                            <Tooltip title={"Approve Registration"}>
                                <IconButton sx={{bgcolor: "#2e7d3224", mx: 1}} color={"success"} onClick={(e) => approveNamespace(e)}><Check/></IconButton>
                            </Tooltip>
                        </>
                    }
                    {
                        (authenticated?.role == "admin" || authenticated?.user == namespace.admin_metadata.user_id) &&
                        <Tooltip title={"Edit Registration"}>
                            <Link href={`/registry/namespace/edit?id=${namespace.id}`}>
                                <IconButton onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                                    <Edit/>
                                </IconButton>
                            </Link>
                        </Tooltip>
                    }
                </Box>
            </Box>
            <Box ref={ref}>
                <InformationDropdown adminMetadata={namespace.admin_metadata} transition={transition} parentRef={ref}/>
            </Box>
        </Box>
    )
}
