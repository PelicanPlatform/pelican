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