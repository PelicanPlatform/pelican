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

import {Box, FormControl, Grid, InputLabel, MenuItem, Select, Typography, Skeleton, Link} from "@mui/material";
import React, {useEffect, useState} from "react";
import {OverridableStringUnion} from "@mui/types";
import {Variant} from "@mui/material/styles/createTypography";
import {TypographyPropsVariantOverrides} from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import {ArrowDropDown, ArrowDropUp} from '@mui/icons-material';
import {fontSize} from "@mui/system"
import {isLoggedIn} from "@/helpers/login";

type duration = number | `${number}${"ns" | "us" | "µs" | "ms" |"s" | "m" | "h"}`;

export type Config = {
    [key: string]: ConfigValue
}

type ConfigValue = Config | string | number | boolean | null | string[] | number[] | duration


function sortConfig (a: [string, ConfigValue], b: [string, ConfigValue]) {

    let isConfig = (value: ConfigValue) => { return typeof value == 'object' && value !== null && !Array.isArray(value)}

    if(isConfig(a[1]) && !isConfig(b[1])){
        return 1
    }
    if(!isConfig(a[1]) && isConfig(b[1])){
        return -1
    }
    return a[0].localeCompare(b[0])
}


interface ConfigDisplayProps {
    id: string[]
    name: string
    value: Config | ConfigValue
    level: number
}

function ConfigDisplay({id, name, value, level = 1}: ConfigDisplayProps) {

    if(name != "") {
        id = [...id, name]
    }

    let formElement = undefined

    if(
        typeof value === 'string' || typeof value === 'number' || value === null
    ){

        // Convert empty values to a space so that the text field is not collapsed
        switch (value){
            case "":
                value = " "
                break
            case null:
                value = "None"
        }

        formElement = <TextField
            fullWidth
            disabled
            size="small"
            id={`${id.join("-")}-text-input`}
            label={name}
            variant={"outlined"}
            value={value}
        />
    } else if(Array.isArray(value)){
        formElement = <TextField
            fullWidth
            disabled
            size="small"
            id={`${id.join("-")}-text-input`}
            label={name}
            variant={"outlined"}
            value={value.join(", ")}
        />
    } else if(typeof value === 'boolean'){
        formElement = (
            <FormControl fullWidth>
                <InputLabel id={`${id.join("-")}-number-input`}>{name}</InputLabel>
                <Select
                    disabled
                    size="small"
                    labelId={`${id.join("-")}-number-input-label`}
                    id={`${id.join("-")}-number-input`}
                    label={name}
                    value={value ? 1 : 0}
                >
                    <MenuItem value={1}>True</MenuItem>
                    <MenuItem value={0}>False</MenuItem>
                </Select>
            </FormControl>
        )
    }

    if(formElement !== undefined){
        return (
            <Box pt={2} id={id.join("-")}>
                {formElement}
            </Box>
        )
    }

    let subValues = Object.entries(value)
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
    if(value !== null && !Array.isArray(value) && typeof value == 'object'){
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

    useEffect(() => {
        getConfig()
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
        <Box width={"100%"}>
            <Typography variant={"h4"} component={"h2"} mb={1}>Configuration</Typography>
            <Grid container spacing={2}>
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
    )
}
