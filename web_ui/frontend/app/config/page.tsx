/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

"use client"

import {
    Box,
    Grid,
    Typography,
    Skeleton,
    Link,
    Container,
    Tooltip,
    Snackbar,
    Button,
    IconButton
} from "@mui/material";
import React, {useContext, useEffect, useMemo, useState} from "react";
import {OverridableStringUnion} from "@mui/types";
import {Variant} from "@mui/material/styles/createTypography";
import {TypographyPropsVariantOverrides} from "@mui/material/Typography";
import {
    AppRegistration,
    ArrowDropDown,
    ArrowDropUp,
    AssistantDirection,
    QuestionMark,
    TripOrigin,
    Cached,
    Download
} from '@mui/icons-material';
import {default as NextLink} from "next/link";
import useSWR from "swr";
import {merge, isMatch} from "lodash"
import * as yaml from "js-yaml"
import {Sidebar} from "@/components/layout/Sidebar";
import {Main} from "@/components/layout/Main";
import {Field} from "@/components/Config";
import {submitConfigChange} from "@/components/Config/util";
import {ParameterInputProps, Config, ConfigMetadata} from "@/components/Config/index.d";
import {getConfigMetadata} from "./util";
import StatusSnackBar, {StatusSnackBarProps} from "@/components/StatusSnackBar";
import {useRouter} from "next/navigation";
import {ServerType} from "@/index";
import {getEnabledServers} from "@/helpers/util";
import DownloadButton from "@/components/DownloadButton";

function Config() {

    const router = useRouter()

    const [status, setStatus] = useState<StatusSnackBarProps|undefined>(undefined)
    const [config, setConfig] = useState<Config | undefined>(undefined)

    // Config state managers
    const [configKey, setConfigKey] = useState<number>(0)

    const [patch, setPatch] = useState<any>({})

    let onChange = (fieldPatch: any) => {
        const newPatch = merge(patch, fieldPatch)
        setPatch(structuredClone(newPatch))
    }

    const {data: enabledServers} = useSWR<ServerType[]>("getEnabledServers", getEnabledServers, {
        fallbackData: ["origin", "registry", "director"]
    })
    const {data: configMetadata} = useSWR<ConfigMetadata | undefined>("getConfigMetadata", getConfigMetadata)

    const getConfig = async () => {
        let response = await fetch("/api/v1.0/config")
        if(response.ok){
            const data = await response.json()
            setConfig(data)
            setStatus(undefined)
            setConfigKey(configKey + 1)
        } else {
            setConfig(undefined)
            if(response.status === 401){
                setStatus({
                    severity: "error",
                    message: "Unauthorized",
                    action: {
                        label: "Login",
                        onClick: () => router.push("/login/?returnURL=/view/config/")
                    }
                })
            }
            setTimeout(getConfig, 2000)
        }
    }

    useEffect(() => {
        getConfig()
    }, [])

    const filteredConfig = useMemo(() => {

        if(!config) {
            return undefined
        }

        if(!enabledServers || !configMetadata) {
            return config
        }

        // Filter out the inactive config values
        const filteredConfig: Config = structuredClone(config)
        Object.entries(configMetadata).forEach(([key, value]) => {

            if([...enabledServers, "*"].filter(i => value.components.includes(i)).length === 0) {
                deleteKey(filteredConfig, key.split("."))
            } else {
                updateValue(filteredConfig, key.split("."), configMetadata[key])
            }
        })

        // Filter out read-only values
        deleteKey(filteredConfig, ["ConfigDir"])

        return filteredConfig

    }, [config, enabledServers, configMetadata])

    return (
        <>
            <Sidebar>
                {enabledServers && enabledServers.includes("origin") &&
                    <Box pt={1}>
                        <NextLink href={"/origin/"}>
                            <Tooltip title={"Origin"} placement={"right"}>
                                <IconButton>
                                    <TripOrigin/>
                                </IconButton>
                            </Tooltip>
                        </NextLink>
                    </Box>
                }
                {enabledServers && enabledServers.includes("director") &&
                    <Box pt={1}>
                        <NextLink href={"/director/"}>
                            <Tooltip title={"Director"} placement={"right"}>
                                <IconButton>
                                    <AssistantDirection/>
                                </IconButton>
                            </Tooltip>
                        </NextLink>
                    </Box>
                }
                {enabledServers && enabledServers.includes("registry") &&
                    <Box pt={1}>
                        <NextLink href={"/registry/"}>
                            <Tooltip title={"Registry"} placement={"right"}>
                                <IconButton>
                                    <AppRegistration/>
                                </IconButton>
                            </Tooltip>
                        </NextLink>
                    </Box>
                }
                {enabledServers && enabledServers.includes("cache") &&
                    <Box pt={1}>
                        <NextLink href={"/cache/"}>
                            <Tooltip title={"Cache"} placement={"right"}>
                                <IconButton>
                                    <Cached/>
                                </IconButton>
                            </Tooltip>
                        </NextLink>
                    </Box>
                }
            </Sidebar>
            <Main>
                <Container maxWidth={"xl"}>
                    <Box width={"100%"}>
                        <Grid container spacing={2}>
                            <Grid item xs={7} md={8} lg={6}>
                                <Box display={"flex"} flexDirection={"row"}>
                                    <Typography variant={"h4"} component={"h2"} mb={1}>Configuration</Typography>
                                    {
                                        config &&
                                        <Box ml={2}>
                                            <DownloadButton
                                                Button={IconButton}
                                                mimeType={"text/yaml"}
                                                data={yaml.dump(stripNulls(stripTypes(structuredClone(config))))}
                                            >
                                                <Download/>
                                            </DownloadButton>
                                        </Box>
                                    }
                                </Box>
                            </Grid>
                            <Grid  item xs={5} md={4} lg={3}></Grid>
                            <Grid item xs={12} md={8} lg={6}>
                                <form>
                                    {
                                        filteredConfig === undefined ?
                                            <Skeleton  variant="rectangular" animation="wave" height={"1000px"}/> :
                                            <ConfigDisplay key={configKey.toString()} id={[]} name={""} value={filteredConfig} level={4} onChange={onChange}/>
                                    }
                                </form>
                                <Snackbar
                                    anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
                                    open={!isMatch(config === undefined ? {} : config, patch)}
                                    message="Save Changes"
                                    action={
                                        <Box>
                                            <Button
                                                onClick={async () => {
                                                    try {
                                                        await submitConfigChange(patch)
                                                        setPatch({})
                                                        setStatus({message: "Changes Saved, Restarting Server"})
                                                        setTimeout(getConfig, 3000)
                                                    } catch (e) {
                                                        setStatus({
                                                            severity: "error",
                                                            message: (e as string).toString()
                                                        })
                                                    }
                                                }}
                                            >
                                                Save
                                            </Button>
                                            <Button
                                                onClick={() => {
                                                    setPatch({})
                                                    getConfig()
                                                }}
                                            >
                                                Clear
                                            </Button>
                                        </Box>
                                    }
                                />
                                {
                                    status &&
                                    <StatusSnackBar key={status.message} {...status} />
                                }
                            </Grid>
                            <Grid item xs={12} md={4} lg={3} display={{ xs: "none", md: "block"}}>
                                {
                                    filteredConfig === undefined ?
                                        <Skeleton  variant="rectangular" animation="wave" height={"1000px"}/> :
                                        <Box pt={2}><TableOfContents id={[]} name={""} value={filteredConfig} level={1}/></Box>
                                }
                            </Grid>
                        </Grid>
                    </Box>
                </Container>
            </Main>
        </>
    )
}

/**
 * Recursively replace all objects of type { Type: any, Value: any } with the value of Value
 * @param config
 */
const stripTypes = (config: any) => {

    if(config?.Value !== undefined && config?.Type !== undefined){
        return config.Value
    }

    Object.keys(config).forEach(key => {
        config[key] = stripTypes(config[key])
    })

    return config
}

/** Recursively delete the keys that have null values in an object */
const stripNulls = (config: any) => {

    // If the config is an object then iterate keys otherwise skip
    if(typeof config !== "object"){
        return config
    }

    Object.keys(config).forEach(key => {
        if(config[key] === null){
            delete config[key]
        } else {
            config[key] = stripNulls(config[key])
        }
    })

    return config
}

const isConfig = (value: ParameterInputProps | Config): boolean => {
    const isConfig = (value as Config)?.Type === undefined
    return isConfig
}

function sortConfig (a: [string, ParameterInputProps | Config], b: [string, ParameterInputProps | Config]) {

    if(isConfig(a[1]) && !isConfig(b[1])){
        return 1
    }
    if(!isConfig(a[1]) && isConfig(b[1])){
        return -1
    }
    return a[0].localeCompare(b[0])
}

interface StringObject {
    [key: string]: any
}

function deleteKey (obj: StringObject, key: string[]) {
    if(key.length === 1) {
        delete obj[key[0]]
        return
    } else {
        deleteKey(obj[key[0]], key.slice(1))
        if(Object.keys(obj[key[0]]).length === 0){
            delete obj[key[0]]
        }
    }
}

function updateValue (obj: StringObject, key: string[], value: any) {
    if(key.length === 1) {
        obj[key[0]] = {...value, ...obj[key[0]]}
        return
    } else {
        updateValue(obj[key[0]], key.slice(1), value)
    }
}

export interface ConfigDisplayProps {
    id: string[]
    name: string
    value: Config | ParameterInputProps
    level: number
    onChange: (patch: any) => void
}

function ConfigDisplay({id, name, value, level = 1, onChange}: ConfigDisplayProps) {

    if(name != "") {
        id = [...id, name]
    }

    // If this is a ConfigValue then display it
    if(!isConfig(value)){
        return (
            <Box pt={2} display={"flex"} id={id.join("-")}>
                <Box flexGrow={1} minWidth={0}>
                    <Field {...value as ParameterInputProps} onChange={onChange} />
                </Box>

                <Button
                    size={"small"}
                    href={`https://docs.pelicanplatform.org/parameters#${id.join("-")}`}
                    target={"_blank"}
                >
                    <QuestionMark/>
                </Button>

            </Box>
        )
    }

    // If this is a Config then display all of its values
    let subValues = Object.entries(value)
    subValues.sort(sortConfig)

    let configDisplays = subValues.map(([k, v]) => {return <ConfigDisplay id={id} key={k} name={k} value={v} level={level+1} onChange={onChange}/>})

    let variant:  OverridableStringUnion<"inherit" | Variant, TypographyPropsVariantOverrides>
    switch (level) {
        case 1:
            variant = "h1"
            break
        case 2:
            variant = "h2"
            break
        case 3:
            variant = "h3"
            break
        case 4:
            variant = "h4"
            break
        case 5:
            variant = "h5"
            break
        case 6:
            variant = "h6"
            break
        default:
            variant = "h6"
    }

    return (
        <>
            { name ? <Typography id={id.join("-")} variant={variant} component={variant} mt={2}>{name}</Typography> : undefined}
            {configDisplays}
        </>
    )

}

interface TableOfContentsProps {
    id: string[]
    name: string
    value: Config | ParameterInputProps
    level: number
}

function TableOfContents({id, name, value, level = 1}: TableOfContentsProps) {

    const [open, setOpen] = useState(false)

    if(name != "") {
        id = [...id, name]
    }

    let subContents = undefined
    if(isConfig(value)){
        let subValues = Object.entries(value)
        subValues.sort(sortConfig)
        subContents = subValues.map(([key, value]) => {
            return <TableOfContents id={id} key={key} name={key} value={value} level={level+1}/>
        })
    }

    let headerPointer = (
        <Box
            sx={{
                "&:hover": {
                    backgroundColor: "primary.light",
                },
                borderRadius: 1,
                paddingX: "5px",
                paddingLeft: 0+5*level + "px"
            }}
        >
            <Link
                href={subContents ? undefined : `#${id.join("-")}`}
                sx={{
                    cursor: "pointer",
                    textDecoration: "none",
                    color: "black",
                    display: "flex",
                    flexDirection: "row",
                    justifyContent: "space-between",
                }}
                onClick={() => {
                    setOpen(!open)
                }}
            >
                <Typography
                    style={{
                        fontSize: 20 - 2*level + "px",
                        fontWeight: subContents ? "600" : "normal",
                    }}
                >
                    {name}
                </Typography>
                {
                    subContents ?
                        open ? <ArrowDropUp/> : <ArrowDropDown/> :
                        undefined
                }
            </Link>
        </Box>
    )

    return (
        <>
            { name ? headerPointer : undefined}
            { subContents && level != 1  ?
                <Box sx={{
                    display: open ? "block" : "none",
                    cursor: "pointer"
                }}
                >
                    {subContents}
                </Box> :
                subContents
            }
        </>
    )
}

export default Config;
