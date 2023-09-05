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

import {Box, Typography} from "@mui/material";
import { useRouter } from 'next/navigation'
import { useState } from "react";

import CodeInput from "@/app/initialization/code/CodeInput";
import LoadingButton from "@/app/initialization/code/LoadingButton";

export default function Home() {

    const router = useRouter()
    let [code, _setCode] = useState <number>(0)
    let [loading, setLoading] = useState(false);

    const setCode = (code: number) => {

        _setCode(code)

        if(code.toString().length == 6) {
            submit(code)
        }
    }

    async function submit(code: number) {

        setLoading(true)

        console.log(`Submitting code ${code}`)

        let response = await fetch("/api/v1.0/origin-ui/initLogin", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "code": code.toString()
            })
        })

        if(response.ok){
            router.push("../password/index.html")
        } else {
            setLoading(false)
        }
    }

    function onSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault()

        if(code.toString().length == 6) {
            submit(code)
        }
    }

    return (
        <>
            <Box m={"auto"} mt={12}  display={"flex"} flexDirection={"column"}>
                <Box>
                    <Typography textAlign={"center"} variant={"h3"} component={"h3"}>
                        Activate Origin Website
                    </Typography>
                    <Typography textAlign={"center"} variant={"h6"} component={"p"}>
                        Enter the activation code displayed on the command line
                    </Typography>
                </Box>
                <Box pt={3} mx={"auto"}>
                    <form onSubmit={onSubmit} action="#">
                        <CodeInput setCode={setCode} length={6}/>
                        <Box mt={3} display={"flex"}>
                            <LoadingButton
                                variant="outlined"
                                sx={{margin: "auto"}}
                                color={"primary"}
                                type={"submit"}
                                loading={loading}
                            >
                                <span>Activate</span>
                            </LoadingButton>
                        </Box>
                    </form>

                </Box>
            </Box>
        </>
    )
}
