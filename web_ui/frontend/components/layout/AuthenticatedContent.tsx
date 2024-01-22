import {Box, BoxProps, Skeleton} from "@mui/material";
import {useEffect, useState} from "react";
import {isLoggedIn} from "@/helpers/login";

const AuthenticatedContent = ({...props} : BoxProps) => {

    const [authenticated, setAuthenticated] = useState<boolean | undefined>(undefined)

    useEffect(() => {
        (async () => {
            const loggedIn = await isLoggedIn()
            setAuthenticated(loggedIn)
            if(!loggedIn){
                window.location.replace("/view/login/index.html")
            }
        })()
    }, []);

    if(authenticated === false){
        return null
    }

    return (
        <Box {...props}>
            {authenticated === undefined && <Skeleton variant="rounded" height={"95vh"} width={"100%"} />}
            {authenticated && props.children}
        </Box>
    )
}

export default AuthenticatedContent
