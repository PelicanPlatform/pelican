'use client'

import LaunchIcon from '@mui/icons-material/Launch';
import {useEffect, useState} from "react";
import {Config} from "@/app/(dashboard)/config/page";
import {Box, Typography} from "@mui/material";
import {isLoggedIn} from "@/helpers/login";
import Link from "next/link";


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

        //Check if the user is logged in
        if(!(await isLoggedIn())){
            window.location.replace("/view/login/")
        }

        let response = await fetch("/api/v1.0/config")
        if(response.ok) {
            const responseData = await response.json() as Config

            setConfig({
                JwkUrl: (responseData?.Federation as Config)?.NamespaceUrl as undefined | string,
                NamespaceUrl: (responseData?.Federation as Config)?.NamespaceUrl as undefined | string,
                DirectorUrl: (responseData?.Federation as Config)?.DirectorUrl as undefined | string,
                TopologyNamespaceUrl: (responseData?.Federation as Config)?.TopologyNamespaceUrl as undefined | string,
                DiscoveryUrl: (responseData?.Federation as Config)?.DiscoveryUrl as undefined | string,
            })
        } else {
            console.error("Failed to fetch config for Federation Overview, response status: " + response.status)
        }
    }

    useEffect(() => {
        getConfig()
    }, [])

    if(config === undefined) {
        return
    }

    return (

        <Box>
            {!Object.values(config).every(x => x == undefined) ? <Typography variant="h4">Federation Overview</Typography> : null}
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

        </Box>
    )
}

export default FederationOverview;