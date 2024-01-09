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

import RateGraph from "@/components/graphs/RateGraph";
import StatusBox from "@/components/StatusBox";

import {TimeDuration} from "@/components/graphs/prometheus";

import {
    Box,
    FormControl,
    Grid,
    InputLabel,
    MenuItem,
    Select,
    Typography,
    Skeleton,
    Link,
    Container,
    Tooltip
} from "@mui/material";
import React, {useEffect, useState} from "react";
import {OverridableStringUnion} from "@mui/types";
import {Variant} from "@mui/material/styles/createTypography";
import {TypographyPropsVariantOverrides} from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import {AppRegistration, ArrowDropDown, ArrowDropUp, AssistantDirection, TripOrigin} from '@mui/icons-material';
import {isLoggedIn} from "@/helpers/login";
import {Sidebar} from "@/components/layout/Sidebar";
import Image from "next/image";
import PelicanLogo from "@/public/static/images/PelicanPlatformLogo_Icon.png";
import IconButton from "@mui/material/IconButton";

type duration = number | `${number}${"ns" | "us" | "µs" | "ms" |"s" | "m" | "h"}`;

export type Config = {
    [key: string]: ConfigValue | Config
}

interface ConfigValue {
    Type: "bool" | "time.Duration" | "[]string" | "int" | "string"
    Value: Config | string | number | boolean | null | string[] | number[] | duration
}

const isConfig = (value: ConfigValue | Config): boolean => {
    return (value as Config)?.Type === undefined
}


function sortConfig (a: [string, ConfigValue | Config], b: [string, ConfigValue | Config]) {

    if(isConfig(a[1]) && !isConfig(b[1])){
        return 1
    }
    if(!isConfig(a[1]) && isConfig(b[1])){
        return -1
    }
    return a[0].localeCompare(b[0])
}

const ConfigDisplayFormElement = ({name, id, configValue}:{name: string, id: string[], configValue: ConfigValue}) : JSX.Element => {

    // If the value needs to be represented as a list in a text field
    if(configValue.Type && configValue.Type.includes("[]")){

        // Check for null list value
        if(configValue.Value === null){
            configValue.Value = []
        }

        return <TextField
            fullWidth
            disabled
            size="small"
            id={`${id.join("-")}-text-input`}
            label={name}
            variant={"outlined"}
            value={(configValue.Value as Array<string>).join(", ")}
        />

    // If the value needs to be represented as a select box
    } else if(configValue.Type === "bool"){

        return (
            <FormControl fullWidth>
                <InputLabel id={`${id.join("-")}-number-input-label`}>{name}</InputLabel>
                <Select
                    disabled
                    size="small"
                    labelId={`${id.join("-")}-number-input-label`}
                    id={`${id.join("-")}-number-input`}
                    label={name}
                    value={configValue ? 1 : 0}
                >
                    <MenuItem value={1}>True</MenuItem>
                    <MenuItem value={0}>False</MenuItem>
                </Select>
            </FormControl>
        )

    // Catch all for other types and potentially undefined values
    } else {

        // Convert empty configValues to a space so that the text field is not collapsed
        switch (configValue.Value){
            case "":
                configValue.Value = " "
                break
            case null:
                configValue.Value = "None"
        }

        return <TextField
            fullWidth
            disabled
            size="small"
            id={`${id.join("-")}-text-input`}
            label={name}
            variant={"outlined"}
            value={configValue.Value}
        />
    }
}

interface ConfigDisplayProps {
    id: string[]
    name: string
    value: Config | ConfigValue
    level: number
}

function ConfigDisplay({id, name, value, level = 1}: ConfigDisplayProps) {

    console.log("ConfigDisplay", id, name, value, level)

    if(name != "") {
        id = [...id, name]
    }

    // If this is a ConfigValue then display it
    if(!isConfig(value)){
        return (
            <Box pt={2} id={id.join("-")}>
                <ConfigDisplayFormElement id={id} name={name} configValue={value as ConfigValue}/>
            </Box>
        )
    }

    // If this is a Config then display all of its values
    let subValues = Object.entries(value as Config)
    subValues.sort(sortConfig)

    let configDisplays = subValues.map(([k, v]) => {return <ConfigDisplay id={id} key={k} name={k} value={v} level={level+1}/>})

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
    value: Config | ConfigValue
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

export default function Config() {

    const [config, setConfig] = useState<Config|undefined>(undefined)
    const [enabledServers, setEnabledServers] = useState<string[]>([])
    const [error, setError] = useState<string|undefined>(undefined)

    let getConfig = async () => {

        //Check if the user is logged in
        if(!(await isLoggedIn())){
            window.location.replace("/view/login/")
        }

        let response = await fetch("/api/v1.0/config")
        if(response.ok) {
            setConfig(await response.json())
        } else {
            setError("Failed to fetch config, response status: " + response.status)
        }
    }

    const getEnabledServers = async () => {
        try {
            const res = await fetch("/api/v1.0/servers")
            const data = await res.json()
            setEnabledServers(data)
        } catch {
            setEnabledServers(["origin", "director", "registry"])
        }
    }

    useEffect(() => {
        getConfig()
        getEnabledServers()
    }, [])


    if(error){
        return (
            <Box width={"100%"}>
                <Typography variant={"h4"} component={"h2"} mb={1}>Configuration</Typography>
                <Typography color={"error"} variant={"body1"} component={"p"} mb={1}>Error: {error}</Typography>
            </Box>
        )
    }

    return (
        <>
            <Sidebar>
                <Link href={"/index.html"}>
                    <Image
                        src={PelicanLogo}
                        alt={"Pelican Logo"}
                        width={36}
                        height={36}
                    />
                </Link>
                { enabledServers.includes("origin") &&
                    <Box pt={3}>
                        <Link href={"/view/origin/index.html"}>
                            <Tooltip title={"Origin"} placement={"right"}>
                                <IconButton>
                                    <TripOrigin/>
                                </IconButton>
                            </Tooltip>
                        </Link>
                    </Box>
                }
                { enabledServers.includes("director") &&
                    <Box pt={1}>
                        <Link href={"/view/director/index.html"}>
                            <Tooltip title={"Director"} placement={"right"}>
                                <IconButton>
                                    <AssistantDirection/>
                                </IconButton>
                            </Tooltip>
                        </Link>
                    </Box>
                }
                { enabledServers.includes("registry") &&
                    <Box pt={1}>
                        <Link href={"/view/registry/index.html"}>
                            <Tooltip title={"Registry"} placement={"right"}>
                                <IconButton>
                                    <AppRegistration/>
                                </IconButton>
                            </Tooltip>
                        </Link>
                    </Box>
                }
            </Sidebar>
            <Box component={"main"} pl={"72px"} pb={2} display={"flex"} minHeight={"100vh"} flexGrow={1}>
                <Container maxWidth={"xl"} sx={{"mt": 2 }}>
                    <Box width={"100%"}>
                        <Grid container spacing={2}>
                            <Grid item xs={7} md={8} lg={6}>
                                <Typography variant={"h4"} component={"h2"} mb={1}>Configuration</Typography>
                            </Grid>
                            <Grid  item xs={5} md={4} lg={3}></Grid>
                            <Grid item xs={7} md={8} lg={6}>
                                <form>
                                    {
                                        config === undefined ?
                                            <Skeleton  variant="rectangular" animation="wave" height={"1000px"}/> :
                                            <ConfigDisplay id={[]} name={""} value={config} level={4}/>
                                    }
                                </form>
                            </Grid>
                            <Grid item xs={5} md={4} lg={3}>
                                {
                                    config === undefined ?
                                        <Skeleton  variant="rectangular" animation="wave" height={"1000px"}/> :
                                        <Box pt={2}><TableOfContents id={[]} name={""} value={config} level={1}/></Box>
                                }
                            </Grid>
                        </Grid>
                    </Box>
                </Container>
            </Box>
        </>
    )
}
