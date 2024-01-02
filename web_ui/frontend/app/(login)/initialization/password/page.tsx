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

import {Box, Grow, Typography} from "@mui/material";
import { useRouter } from 'next/navigation'
import { useState } from "react";

import LoadingButton from "../../components/LoadingButton";

import PasswordInput from "../../components/PasswordInput";

export default function Home() {

    const router = useRouter()
    let [password, _setPassword] = useState <string>("")
    let [confirmPassword, _setConfirmPassword] = useState <string>("")
    let [loading, setLoading] = useState(false);
    let [error, setError] = useState<string | undefined>(undefined);

    async function submit(password: string) {

        setLoading(true)

        let response = await fetch("/api/v1.0/auth/resetLogin", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "password": password
            })
        })

        if(response.ok){
            router.push("/")
        } else {
            try {
                let data = await response.json()

                setLoading(false)
                setError(response.status + ": " + data['error'])
            } catch {
                setLoading(false)
                setError(response.status + ": " + response.statusText)
            }
        }
    }

    function onSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault()

        if(password == confirmPassword){
            submit(password)
        } else {
            setError("Passwords do not match")
        }
    }

    return (
        <>
            <Box m={"auto"} mt={12}  display={"flex"} flexDirection={"column"}>
                <Box>
                    <Typography textAlign={"center"} variant={"h3"} component={"h3"}>
                        Set Password
                    </Typography>
                    <Typography textAlign={"center"} variant={"h6"} component={"p"}>
                        This will become the admin password for this Pelican endpoint
                    </Typography>
                </Box>
                <Box pt={2} mx={"auto"}>
                    <form onSubmit={onSubmit} action="#">
                        <Box>
                            <PasswordInput TextFieldProps={{
                                InputProps: {
                                    onChange: (e) => {
                                        _setPassword(e.target.value)
                                        setError(undefined)
                                    }
                                }
                            }}/>
                        </Box>
                        <Box>
                            <PasswordInput TextFieldProps={{
                                label: "Confirm Password",
                                InputProps: {
                                    onChange: (e) => {
                                        _setConfirmPassword(e.target.value)
                                        setError(undefined)
                                    }
                                },
                                error: password != confirmPassword,
                                helperText: password != confirmPassword ? "Passwords do not match" : ""
                            }}/>
                        </Box>
                        <Box mt={2} display={"flex"} flexDirection={"column"}>
                            <Grow in={error !== undefined}>
                                <Typography
                                    textAlign={"center"}
                                    variant={"subtitle2"}
                                    color={"error.main"}
                                    mb={1}
                                >
                                    {error}
                                </Typography>
                            </Grow>
                            <LoadingButton
                                variant="outlined"
                                sx={{margin: "auto"}}
                                color={"primary"}
                                type={"submit"}
                                loading={loading}
                            >
                                <span>Confirm</span>
                            </LoadingButton>
                        </Box>
                    </form>

                </Box>
            </Box>
        </>
    )
}
