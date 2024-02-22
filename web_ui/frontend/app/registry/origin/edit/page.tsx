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
    Button,
    Grid,
    Typography,
    Collapse,
    Alert,
    Skeleton
} from "@mui/material";
import React, {ReactNode, useEffect, useMemo, useState} from "react";

import Link from "next/link";

import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import {secureFetch} from "@/helpers/login";
import {Namespace, Alert as AlertType} from "@/components/Main";
import OriginForm from "@/app/registry/components/OriginForm";

interface Institution {
    id: string;
    name: string;
}

export default function Register() {

    const [id, setId] = useState<string | undefined>(undefined)
    const [namespace, setNamespace] = useState<Namespace | undefined>(undefined)
    const [alert, setAlert] = useState<AlertType | undefined>(undefined)


    useEffect(() => {

        const urlParams = new URLSearchParams(window.location.search);
        const id = urlParams.get('id')

        if(id === null){
            setAlert({severity: "error", message: "No Namespace ID Provided"})
        } else {
            setId(id)
        }

        (async () => {

            const urlParams = new URLSearchParams(window.location.search);
            const id = urlParams.get('id');

            const url = new URL(`/api/v1.0/registry_ui/namespaces/${id}`, window.location.origin)
            const response = await fetch(url)
            if (response.ok) {
                const namespace: Namespace = await response.json()
                setNamespace(namespace)
            } else {
                setAlert({severity: "error", message: `Failed to fetch namespace: ${id}`})
            }
        })()
    }, [id])

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {

        e.preventDefault()

        const formData = new FormData(e.currentTarget);

        try {
            const response = await secureFetch(`/api/v1.0/registry_ui/namespaces/${id}`, {
                body: JSON.stringify({
                    prefix: formData.get("prefix"),
                    pubkey: formData.get("pubkey"),
                    admin_metadata: {
                        description: formData.get("description"),
                        site_name: formData.get("site-name"),
                        institution: formData.get("institution"),
                        security_contact_user_id: formData.get("security-contact-user-id")
                    }
                }),
                method: "PUT",
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
                    setAlert({severity: "error", message: `Failed to edit namespace: ${formData.get("prefix")}`})
                }
            } else {
                setAlert({severity: "success", message: `Successfully edited namespace: ${formData.get("prefix")}`})
                window.location.href = "/view/registry/"
            }

        } catch (e) {
            console.error(e)
            setAlert({severity: "error", message: `Fetch error: ${e}`})
        }

        return false
    }

    return (
        <AuthenticatedContent width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12}>
                    <Typography variant={"h4"} pb={3}>Namespace Registry</Typography>
                </Grid>
                <Grid item xs={12} lg={8} justifyContent={"space-between"}>
                    <Typography variant={"h5"} pb={3}>Register Namespace</Typography>
                    <Collapse in={alert !== undefined}>
                        <Box mb={2}>
                            <Alert severity={alert?.severity}>{alert?.message}</Alert>
                        </Box>
                    </Collapse>
                    {
                        namespace ?
                        <OriginForm handleSubmit={handleSubmit} namespace={namespace}/> :
                        <Skeleton variant="rounded" width={"100%"} height={400} />
                    }
                </Grid>
                <Grid item lg={2}>
                </Grid>
            </Grid>
        </AuthenticatedContent>
    )
}
