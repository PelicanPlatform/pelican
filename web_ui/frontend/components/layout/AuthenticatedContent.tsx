"use client"

import {Box, BoxProps, Button, Skeleton, Typography} from "@mui/material";
import useSWR from "swr";
import {getUser} from "@/helpers/login";
import {useEffect, useMemo, useState} from "react";
import Link from "next/link";
import {useRouter} from "next/navigation";
import {User} from "@/index";


const Circle = ({children}: {children: React.ReactNode}) => {
    return (
        <Box display={"flex"} justifyContent={"center"} alignItems={"center"} height={"100%"} width={"100%"}>
            <Box padding={6} borderRadius={"100%"} bgcolor={"primary.light"} sx={{aspectRatio: 1}}>
                <Box display={"flex"} justifyContent={"center"} alignItems={"center"} height={"100%"} flexDirection={"column"}>
                    {children}
                </Box>
            </Box>
        </Box>
    )
}

interface AuthenticatedContentProps {
    promptLogin?: boolean;
    redirect?: boolean;
    children: React.ReactNode;
    boxProps?: BoxProps;
    checkAuthentication?: (user: User) => boolean;
}

const AuthenticatedContent = ({promptLogin = false, redirect = false, children, boxProps, checkAuthentication}: AuthenticatedContentProps) => {

    if(redirect && promptLogin){
        throw new Error("redirect XOR promptLogin must be true")
    }

    const router = useRouter()
    const {data, isValidating, isLoading, error} = useSWR("getUser", getUser, { refreshInterval: 1000 * 60, revalidateOnMount: true })
    const [pageUrl, setPageUrl] = useState<string>("")

    const authenticated = useMemo(() => {
        if(data && checkAuthentication){
            return checkAuthentication(data)
        } else {
            return data?.authenticated
        }
    }, [data, checkAuthentication])

    useEffect(() => {
        // Keep pathname as is since backend handles the redirect after logging in and needs the full path
        const path = window.location.pathname + window.location.search
        const pathUrlEncoded = encodeURIComponent(path)

        setPageUrl(pathUrlEncoded)
    }, []);

    // Redirect to login page if not authenticated and redirect is true
    useEffect(() => {

        if(!isValidating && !authenticated && redirect){
            router.push("/login/?returnURL=" + pageUrl)
        }
    }, [data, isValidating]);

    if(error){
        return (
            <Circle>
                {error}
            </Circle>
        )
    }

    if(data === undefined){
        return <Skeleton variant="rounded" height={"95vh"} width={"100%"} />
    }

    if(authenticated === false && promptLogin){
        return (
            <Circle>
                <Typography variant={"h4"} align={"center"}>
                    Unauthorized
                </Typography>
                <Typography variant={"subtitle1"} align={"center"}>
                    Admin Privileges Required
                </Typography>
                <Box pt={4}>
                    <Link href={`/login/?returnURL=${pageUrl}`}>
                        <Button variant={'contained'}>Login</Button>
                    </Link>
                </Box>
            </Circle>
        )
    }

    return (
        <Box {...boxProps}>
            {authenticated && children}
        </Box>
    )
}

export default AuthenticatedContent
