import {Namespace} from "@/components/Main";
import {Authenticated} from "@/helpers/login";
import React, {useRef, useState} from "react";
import {Avatar, Box, IconButton, Paper, Tooltip, Typography} from "@mui/material";
import {Download, Edit, Person} from "@mui/icons-material";
import Link from "next/link";

import InformationDropdown from "./InformationDropdown";

export const Card = ({
                         namespace,
                         authenticated,
                         editUrl
                     } : {namespace: Namespace, authenticated?: Authenticated, editUrl: string}) => {
    const ref = useRef<HTMLDivElement>(null);
    const [transition, setTransition] = useState<boolean>(false);

    return (
        <Paper elevation={transition ? 2 : 0} sx={{mb:1}}>
            <Box
                sx={{
                    cursor: "pointer",
                    display: "flex",
                    width: "100%",
                    justifyContent: "space-between",
                    border: "solid #ececec 1px",
                    borderRadius: "4px",
                    "&:hover": {
                        bgcolor: "#ececec"
                    },
                    p: 1
                }}
                bgcolor={"secondary"}
                onClick={() => setTransition(!transition)}
            >
                <Box my={"auto"} ml={1} display={"flex"} flexDirection={"row"}>
                    { authenticated !== undefined && authenticated.user == namespace.admin_metadata.user_id &&
                        <Tooltip title={"Created By You"}>
                            <Avatar sx={{height: "25px", width: "25px", my: "auto", mr:2}}>
                                <Person/>
                            </Avatar>
                        </Tooltip>
                    }
                    <Typography>{namespace.prefix}</Typography>
                </Box>
                <Box>
                    <Tooltip title={"Download JWK"}>
                        <Link href={`/api/v1.0/registry_ui/namespaces/${namespace.id}/pubkey`}>
                            <IconButton onClick={(e: React.MouseEvent) => e.stopPropagation()} sx={{mx: 1}}>
                                <Download/>
                            </IconButton>
                        </Link>
                    </Tooltip>
                    {
                        authenticated?.role == "admin" &&
                        <Tooltip title={"Edit Registration"}>
                            <Link href={editUrl}>
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
        </Paper>
    )
}

export default Card;