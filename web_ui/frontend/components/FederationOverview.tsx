'use client'

import LaunchIcon from '@mui/icons-material/Launch';
import {useEffect, useState} from "react";
import {Config} from "./Config/index.d";
import {Box, Typography} from "@mui/material";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import Link from "next/link";
import {getErrorMessage, getObjectValue} from "@/helpers/util";

const LinkBox = ({href, text} : {href: string, text: string}) => {
    return (
        <Link href={href}>
            <Box p={1} px={2} display={"flex"} flexDirection={"row"} bgcolor={"info.light"} borderRadius={2} mb={1}>
                <Typography sx={{pb: 0}}>
                    {text}
                </Typography>
                <Box ml={"auto"} my={"auto"} display={"flex"}>
                    <LaunchIcon/>
                </Box>
            </Box>
        </Link>
    )
}

const UrlData = [
    {key: ["Federation", "NamespaceUrl", "Value"], text: "Namespace Registry"},
    {key: ["Federation", "DirectorUrl", "Value"], text: "Director"},
    {key: ["Federation", "RegistryUrl", "Value"], text: "Registry"},
    {key: ["Federation", "TopologyNamespaceUrl", "Value"], text: "Topology Namespace"},
    {key: ["Federation", "DiscoveryUrl", "Value"], text: "Discovery"},
    {key: ["Federation", "JwkUrl", "Value"], text: "JWK"}
]

const FederationOverview = () => {

    const [config, setConfig] = useState<{text: string, url: string | undefined}[]>([])

    let getConfig = async () => {
        let response = await fetch("/api/v1.0/config")
        if(response.ok) {
            const responseData = await response.json() as Config

            const federationUrls = UrlData.map(({key, text}) => {
                let url = getObjectValue<string>(responseData, key)
                if(url && !url?.startsWith("http://") && !url?.startsWith("https://")) {
                    url = "https://" + url
                }

                return {
                    text,
                    url
                }
            })

            setConfig(federationUrls)

        } else {
            console.error(await getErrorMessage(response))
        }
    }

    useEffect(() => {
        getConfig()
    }, [])

    if(config === undefined) {
        return
    }

    return (

        <AuthenticatedContent redirect={true} checkAuthentication={(u) => u?.role == "admin"}>
            {!Object.values(config).every(x => x == undefined) ? <Typography variant={"h4"} component={"h2"}  mb={2}>Federation Overview</Typography> : null}
            {config.map(({text, url}) => {
                if(url) {
                    return <LinkBox key={text} href={url} text={text}></LinkBox>
                }
            })}
        </AuthenticatedContent>
    )
}

export default FederationOverview;
