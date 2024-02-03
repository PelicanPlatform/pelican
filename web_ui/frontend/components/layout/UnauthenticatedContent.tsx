import {Box, BoxProps, Skeleton, Alert} from "@mui/material";
import {useEffect, useState} from "react";
import {isLoggedIn} from "@/helpers/login";

const UnauthenticatedContent = ({...props} : BoxProps) => {

    const [authenticated, setAuthenticated] = useState<boolean | undefined>(undefined)

    useEffect(() => {
        (async () => {
            const loggedIn = await isLoggedIn()
            setAuthenticated(loggedIn)
        })()
    }, []);

    if(authenticated === true){
        return null
    }

    return (
        <Box {...props}>
            {authenticated === undefined && <Skeleton variant="rounded" height={"50px"} width={"100%"} />}
            {authenticated === false &&
                <Alert severity="info">{props.children}</Alert>
            }
        </Box>
    )
}

export default UnauthenticatedContent
