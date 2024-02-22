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

import {
    Box,
    Grid,
    Typography,
    Collapse,
    Alert
} from "@mui/material";
import React, {ReactNode, useEffect, useMemo, useState} from "react";

import Link from "next/link";

import {Alert as AlertType} from "@/components/Main";
import CacheForm from "@/app/registry/components/CacheForm";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import {secureFetch} from "@/helpers/login";

export default function Register() {

    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) : Promise<boolean> => {

        e.preventDefault()

        const formData = new FormData(e.currentTarget);

        try {
            const response = await secureFetch("/api/v1.0/registry_ui/namespaces", {
                body: JSON.stringify({
                    prefix: `/cache/${formData.get("prefix")}`,
                    pubkey: formData.get("pubkey"),
                    admin_metadata: {
                        description: formData.get("description"),
                        site_name: formData.get("site-name"),
                        institution: formData.get("institution"),
                        security_contact_user_id: formData.get("security-contact-user-id")
                    }
                }),
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "include"
            })

            if(!response.ok){
                try {
                    let data = await response.json()
                    setAlert({severity: "error", message: response.status + ": " + data['error']})
                } catch (e) {
                    setAlert({severity: "error", message: `Failed to register namespace: ${formData.get("prefix")}`})
                }
            } else {
                setAlert({severity: "success", message: `Successfully registered namespace: ${formData.get("prefix")}`})
                return true
            }

        } catch (e) {
            setAlert({severity: "error", message: `Fetch error: ${e}`})
        }

        return false
    }

    return (
        <AuthenticatedContent width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={7}>
                    <Typography variant={"h4"} pb={3}>Register Cache</Typography>
                    <Typography variant={"body1"} pb={2}>
                        Registering a Cache allows the federation to cache its data there.
                    </Typography>
                </Grid>
                <Grid item xs={12} lg={7} justifyContent={"space-between"}>
                    <Collapse in={alert !== undefined}>
                        <Box mb={2}>
                            <Alert severity={alert?.severity}>{alert?.message}</Alert>
                        </Box>
                    </Collapse>
                    <CacheForm handleSubmit={handleSubmit}/>
                </Grid>
                <Grid item lg={2}>
                </Grid>
            </Grid>
        </AuthenticatedContent>
    )
}
