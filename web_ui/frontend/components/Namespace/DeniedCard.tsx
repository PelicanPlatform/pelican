import React, {useMemo, useRef, useState} from "react";
import {green, red} from "@mui/material/colors";
import {Authenticated, secureFetch} from "@/helpers/login";
import {Avatar, Box, IconButton, Tooltip, Typography} from "@mui/material";
import {Block, Check, Delete, Edit, Person} from "@mui/icons-material";
import {Alert as AlertType, Alert, Namespace} from "@/index";
import InformationDropdown from "./InformationDropdown";
import {getServerType, NamespaceIcon} from "@/components/Namespace/index";
import {User} from "@/index";
import AlertPortal from "@/components/AlertPortal";
import { useSWRConfig } from 'swr'

export interface DeniedCardProps {
    namespace: Namespace;
    onUpdate: () => void;
    onAlert: (alert: Alert) => void;
    authenticated?: User
}

const deleteNamespace = async (id: number) => {
    const response = await secureFetch(`/api/v1.0/registry_ui/namespaces/${id}`, {
        method: "DELETE"
    })

    if (!response.ok){
        let alertMessage;
        try {
            let data = await response.json()
            if (data?.msg) {
                alertMessage = data?.msg
            }
            alertMessage = "Details not provided"
        } catch (e) {
            if(e instanceof Error) {
                alertMessage = e.message
            }
        }

        throw new Error("Failed to delete namespace: " + alertMessage)
    }
}

const approveNamespace = async (id: number) => {
    const response = await secureFetch(`/api/v1.0/registry_ui/namespaces/${id}/approve`, {
        method: "PATCH"
    })

    if (!response.ok){
        let alertMessage;
        try {
            let data = await response.json()
            if (data?.msg) {
                alertMessage = data?.msg
            }
            alertMessage = "Details not provided"
        } catch (e) {
            if(e instanceof Error) {
                alertMessage = e.message
            }
        }

        throw new Error("Failed to approve registration: " + alertMessage)
    }
}

export const DeniedCard = ({
                                namespace,
                                authenticated
                            }: DeniedCardProps) => {

    const ref = useRef<HTMLDivElement>(null);
    const [transition, setTransition] = useState<boolean>(false);
    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

    const { mutate } = useSWRConfig()

    return (
        <>
            <Box>
                <Box sx={{
                    cursor: "pointer",
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: transition ? "10px 10px 0px 0px" : 2,
                    transition: "background-color .3s ease-out",
                    bgcolor: alert?.severity == "success" ? green[100] : alert?.severity == "error" ? red[100] : "inherit",
                    "&:hover": {
                        bgcolor: alert ? undefined : "#ececec"
                    },
                    p: 1
                }}
                     bgcolor={"secondary"}
                     onClick={() => setTransition(!transition)}
                >
                    <Box my={"auto"} ml={1} display={"flex"} flexDirection={"row"}>
                        <NamespaceIcon serverType={namespace.type} />
                        <Typography sx={{pt: "2px"}}>{namespace.prefix}</Typography>
                    </Box>
                    <Box display={"flex"}>
                        <Box my={"auto"} display={"flex"} flexDirection={"row"}>
                            { authenticated !== undefined && authenticated.user == namespace.admin_metadata.user_id &&
                                <Box sx={{borderRight: "solid 1px #ececec", mr: 1}}>
                                    <Tooltip title={"Created By You"}>
                                        <Avatar sx={{height: "40px", width: "40px", my: "auto", mr:2}}>
                                            <Person/>
                                        </Avatar>
                                    </Tooltip>
                                </Box>
                            }
                            { authenticated?.role == "admin" &&
                                <>
                                    <Tooltip title={"Delete Registration"}>
                                        <IconButton
                                            sx={{bgcolor: "#ff00001a", mx: 1}}
                                            color={"error"}
                                            onClick={async (e) => {
                                                e.stopPropagation()
                                                try {
                                                    await deleteNamespace(namespace.id)
                                                    setAlert({severity: "success", message: "Registration deleted"})
                                                    setTimeout(() =>  mutate("getNamespaces"), 600)
                                                } catch (e) {
                                                    if(e instanceof Error){
                                                        setAlert({severity: "error", message: e.message})
                                                    }
                                                }
                                            }}
                                        >
                                            <Delete/>
                                        </IconButton>
                                    </Tooltip>
                                    <Tooltip title={"Approve Registration"}>
                                        <IconButton
                                            sx={{bgcolor: "#2e7d3224", mx: 1}}
                                            color={"success"}
                                            onClick={async (e) => {
                                                e.stopPropagation()
                                                try {
                                                    await approveNamespace(namespace.id)
                                                    setAlert({severity: "success", message: "Registration Approved"})
                                                    setTimeout(() =>  mutate("getNamespaces"), 600)
                                                } catch (e) {
                                                    if(e instanceof Error){
                                                        setAlert({severity: "error", message: e.message})
                                                    }
                                                }
                                            }}
                                        >
                                            <Check/>
                                        </IconButton>
                                    </Tooltip>
                                </>
                            }
                        </Box>
                    </Box>
                </Box>
                <Box ref={ref}>
                    <InformationDropdown adminMetadata={namespace.admin_metadata} transition={transition} parentRef={ref}/>
                </Box>
            </Box>
            { alert?.severity == "error" &&
                <AlertPortal key={JSON.stringify(alert)} alert={alert} onClose={() => setAlert(undefined)} />
            }
        </>

    )
}

export default DeniedCard;
