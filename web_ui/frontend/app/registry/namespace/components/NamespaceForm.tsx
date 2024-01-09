import {
    Box,
    Button,
    FormControl,
    FormHelperText,
    InputLabel,
    MenuItem,
    Select,
    TextareaAutosize,
    TextField
} from "@mui/material";
import React, {useEffect, useState} from "react";
import {getServerType} from "@/components/Namespace";
import {Namespace} from "@/components/Main";

interface Institution {
    id: string;
    name: string;
}

interface NamespaceFormProps {
    namespace?: Namespace;
    handleSubmit: (e: React.FormEvent<HTMLFormElement>) => Promise<boolean>;
}

const NamespaceForm = ({
    namespace,
    handleSubmit
}: NamespaceFormProps) => {

    const [institutions, setInstitutions] = useState<Institution[]>([])
    const [institution, setInstitution] = useState<string>(namespace?.admin_metadata?.institution || '')
    const [serverType, setServerType] = useState<"origin" | "cache" | ''>(namespace !== undefined ? getServerType(namespace) : "")

    useEffect(() => {
        (async () => {
            const url = new URL("/api/v1.0/registry_ui/institutions", window.location.origin)
            const response = await fetch(url)
            if (response.ok) {
                const responseData: Institution[] = await response.json()
                setInstitutions(responseData)
            }
        })()
    }, []);

    const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {

        const form = e.currentTarget

        const successfulSubmit = await handleSubmit(e)

        // Clear the form on successful submit
        if (successfulSubmit) {
            form.reset()
            setInstitution("")
            setServerType("")
        }
    }

    return (
        <form onSubmit={onSubmit}>
            <Box pb={2}>
                <TextField
                    fullWidth
                    size={"small"}
                    id={"prefix"}
                    name={"prefix"}
                    label={"Prefix"}
                    defaultValue={namespace?.prefix || ""}
                    variant={"outlined"}
                    onChange={event => {
                        if (event.target.value == "") {
                            setServerType("")
                        } else if (event.target.value.startsWith("/cache")) {
                            setServerType("cache")
                        } else {
                            setServerType("origin")
                        }
                    }}
                />
            </Box>
            <Box pb={2}>
                <FormControl fullWidth size={"small"}>
                    <InputLabel id="institution-label">Namespace Type</InputLabel>
                    <Select
                        labelId="institution-label"
                        id="institution"
                        label="Institution"
                        value={serverType}
                        inputProps={{readOnly: true}}
                    >
                        <MenuItem value={"cache"}>Cache</MenuItem>
                        <MenuItem value={"origin"}>Origin</MenuItem>
                    </Select>
                    <FormHelperText>Read Only: Caches are declared with a &apos;/cache&apos; prefix</FormHelperText>
                </FormControl>
            </Box>
            <Box pb={2}>
                <TextField
                    fullWidth
                    size={"small"}
                    id={"pubkey"}
                    name={"pubkey"}
                    label={"Pubkey"}
                    variant={"outlined"}
                    multiline={true}
                    defaultValue={namespace?.pubkey || ""}
                    inputProps={{
                        style: {
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            lineHeight: "0.9rem",
                            minHeight: "1.5rem"
                        }
                    }}
                />
            </Box>
            <Box pb={2}>
                <TextField
                    fullWidth
                    size={"small"}
                    id={"description"}
                    name={"description"}
                    label={"Description"}
                    variant={"outlined"}
                    defaultValue={namespace?.admin_metadata?.description || ""}
                />
            </Box>
            <Box pb={2}>
                <TextField
                    fullWidth
                    size={"small"}
                    id={"site-name"}
                    name={"site-name"}
                    label={"Site Name"}
                    variant={"outlined"}
                    defaultValue={namespace?.admin_metadata?.site_name || ""}
                />
            </Box>
            <Box pb={2}>
                <FormControl fullWidth size={"small"}>
                    <InputLabel id="institution-label">Institution</InputLabel>
                    <Select
                        labelId="institution-label"
                        id="institution"
                        name={"institution"}
                        label="Institution"
                        value={institution}
                        onChange={event => setInstitution(event.target.value as string)}
                    >
                        {institutions.map(institution => <MenuItem key={institution.id}
                                                                   value={institution.id}>{institution.name}</MenuItem>)}
                    </Select>
                </FormControl>
            </Box>
            <Box pb={2}>
                <TextField
                    fullWidth
                    size={"small"}
                    id={"Security Contact ID"}
                    name={"security-contact-user-id"}
                    label={"Security Contact ID"}
                    variant={"outlined"}
                    defaultValue={namespace?.admin_metadata?.security_contact_user_id || ""}
                />
            </Box>
            <Box pb={2}>
                <Button type={"submit"} variant={"contained"}>Submit</Button>
            </Box>
        </form>
    )
}

export default NamespaceForm