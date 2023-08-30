"use client"

import {useState} from "react";
import Button from "@mui/material/Button";
import CircularProgress from "@mui/material/CircularProgress";

interface LoadingButtonProps extends React.ComponentProps<typeof Button> {
    loading: boolean;
}

export default function LoadingButton({loading, ...props}: LoadingButtonProps) {

    /**
     * Prevents the button from being clicked while loading
     * @param e
     */
    function onClick(e: React.MouseEvent<HTMLButtonElement>) {
        if(loading){
            e.preventDefault()
            return
        }
    }

    return (
        <Button
            onClick={onClick}
            variant="outlined"
            {...props}
        >
            {loading ? <CircularProgress size={"1.5rem"}/> : props.children }
        </Button>
    )
}