'use client'

import LaunchIcon from '@mui/icons-material/Launch';
import {useEffect, useState} from "react";
import {Config} from "./Config/index.d";
import {Box, Typography} from "@mui/material";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import Link from "next/link";
import {getErrorMessage} from "@/helpers/util";


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

const FederationOverview = () => {

    const [config, setConfig] = useState<{ [key: string] : string | undefined} | undefined>(undefined)

    let getConfig = async () => {
        let response = await fetch("/api/v1.0/config")
        if(response.ok) {
            const responseData = await response.json() as Config

            setConfig({
                JwkUrl: (responseData?.Federation as Config)?.NamespaceUrl?.Value as undefined | string,
                NamespaceUrl: (responseData?.Federation as Config)?.NamespaceUrl?.Value as undefined | string,
                DirectorUrl: (responseData?.Federation as Config)?.DirectorUrl?.Value as undefined | string,
                TopologyNamespaceUrl: (responseData?.Federation as Config)?.TopologyNamespaceUrl?.Value as undefined | string,
                DiscoveryUrl: (responseData?.Federation as Config)?.DiscoveryUrl?.Value as undefined | string,
            })
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
            {config?.NamespaceUrl ?
                <LinkBox href={config?.NamespaceUrl} text={"Namespace Registry"}/> : null
            }
            {config?.DirectorUrl ?
                <LinkBox href={config?.DirectorUrl} text={"Director"}/> : null
            }
            {config?.TopologyNamespaceUrl ?
                <LinkBox href={config?.TopologyNamespaceUrl} text={"Topology Namespace"}/> : null
            }
            {config?.DiscoveryUrl ?
                <LinkBox href={config?.DiscoveryUrl} text={"Discovery"}/> : null
            }
            {config?.JwkUrl ?
                <LinkBox href={config?.JwkUrl} text={"JWK"}/> : null
            }
        </AuthenticatedContent>
    )
}

export default FederationOverview;
