"use client"

import React, {useMemo} from "react";
import {Face2, Face3, Face4, Face5, Face6} from "@mui/icons-material";

const RandomUserIcon = () => {

    // Pick a random icon for the user
    const iconIndex = useMemo(() => {
        // Get random number between 0 and 4
        return Math.floor(Math.random() * 5)
    }, [])

    const userIcons = [
        <Face2 key={"face2"}/>,
        <Face3 key={"face3"}/>,
        <Face4 key={"face4"}/>,
        <Face5 key={"face5"}/>,
        <Face6 key={"face6"}/>
    ]

    return userIcons[iconIndex]
}

export default RandomUserIcon
export {RandomUserIcon}
