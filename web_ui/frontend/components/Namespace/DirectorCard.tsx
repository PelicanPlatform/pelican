import {Namespace} from "@/components/Main";
import {Authenticated, secureFetch} from "@/helpers/login";
import React, {useRef, useState} from "react";
import {
    Avatar,
    Box,
    IconButton,
    Paper,
    Tooltip,
    Typography,
    Switch,
    Snackbar,
    FormGroup,
    FormControlLabel, Portal, Alert
} from "@mui/material";
import {Server} from "@/components/Main";
import {Language} from "@mui/icons-material";
import {NamespaceIcon} from "@/components/Namespace/index";
import useSWR from "swr";
import Link from "next/link";

export interface DirectorCardProps {
    server: Server
    authenticated?: Authenticated
}

export const DirectorCard = ({ server, authenticated } : DirectorCardProps) => {

    const [filtered, setFiltered] = useState<boolean>(server.filtered);
    const [error, setError] = useState<string | undefined>(undefined);
    const [disabled, setDisabled] = useState<boolean>(false);

    const {mutate} = useSWR<Server[]>("getServers")

    return (
        <>
            <Paper>
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
                >
                    <Box my={"auto"} ml={1} display={"flex"} flexDirection={"row"}>
                        <NamespaceIcon serverType={server.type.toLowerCase() as "cache" | "origin"} />
                        <Typography sx={{pt: "2px"}}>{server.name}</Typography>
                    </Box>
                    <Box display={"flex"} flexDirection={"row"}>
                        <Box my={"auto"} display={"flex"}>
                            {(authenticated && authenticated.role == "admin") &&
                                <FormGroup>
                                    <FormControlLabel
                                        labelPlacement="start"
                                        control={
                                            <Switch
                                                key={server.name}
                                                disabled={disabled}
                                                checked={!filtered}
                                                color={"success"}
                                                onClick={async (x) => {

                                                    x.stopPropagation()

                                                    // Disable the switch
                                                    setDisabled(true)

                                                    // Provide optimistic feedback
                                                    setFiltered(!filtered)

                                                    // Update the server
                                                    let error;
                                                    if(filtered) {
                                                        error = await allowServer(server.name)
                                                    } else {
                                                        error = await filterServer(server.name)
                                                    }

                                                    // Revert if we were too optimistic
                                                    if(error) {
                                                        setFiltered(!filtered)
                                                        setError(error)
                                                    } else {
                                                        mutate()
                                                    }

                                                    setDisabled(false)
                                                }}
                                            />
                                        }
                                        label={!filtered ? "Active" : "Disabled"}
                                    />
                                </FormGroup>
                            }
                            { server?.webUrl &&
                                <Box ml={1}>
                                    <Link href={server.webUrl} target={"_blank"} >
                                        <Tooltip title={"View Server Website"}>
                                            <IconButton>
                                                <Language/>
                                            </IconButton>
                                        </Tooltip>
                                    </Link>
                                </Box>
                            }
                        </Box>
                    </Box>
                </Box>
            </Paper>
            <Portal>
                <Snackbar
                    anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
                    open={error !== undefined}
                    onClose={() => setError(undefined)}
                >
                    <Alert
                        onClose={() => setError(undefined)}
                        severity="error"
                        variant="filled"
                        sx={{ width: '100%' }}
                    >
                        {error}<br/>If this error persists on reload, please file a ticket via the (?) in the bottom left.
                    </Alert>
                </Snackbar>
            </Portal>
        </>
    )
}

const filterServer = async (name: string) => {
    try {
        const response = await secureFetch(
            `/api/v1.0/director_ui/servers/filter/${name}`,
            {
                method: "PATCH"
            }
        )
        if (response.ok) {
            return
        } else {
            const data = await response.json()
            return data?.error
        }
    } catch (e) {
        return e
    }
}

const allowServer = async (name: string) => {
    try {
        const response = await secureFetch(
            `/api/v1.0/director_ui/servers/allow/${name}`,
            {
                method: "PATCH"
            }
        )
        if (response.ok) {
            return
        } else {
            const data = await response.json()
            return data?.error
        }
    } catch (e) {
        return e
    }
}

export default DirectorCard;
