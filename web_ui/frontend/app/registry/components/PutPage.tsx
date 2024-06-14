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
    Alert,
    Skeleton
} from "@mui/material";
import React, {ReactNode, Suspense, useEffect, useMemo, useState} from "react";

import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import {Namespace, Alert as AlertType} from "@/index";
import Form from "@/app/registry/components/Form";
import {getNamespace, submitNamespaceForm} from "@/app/registry/components/util";
import type {NamespaceFormPage} from "./CustomRegistrationField/index.d";

const PutPage = ({update}: NamespaceFormPage) => {

    const [id, setId] = useState<number | undefined>(undefined)
    const [fromUrl, setFromUrl] = useState<URL | undefined>(undefined)
    const [namespace, setNamespace] = useState<Namespace | undefined>(undefined)
    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

    useEffect(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const id = urlParams.get('id')
        const fromUrl = urlParams.get('fromUrl')

        if (id === null) {
            setAlert({severity: "error", message: "No Namespace ID Provided"})
            return
        }

        try {
            if (fromUrl != undefined) {
                const parsedUrl = new URL(fromUrl)
                setFromUrl(parsedUrl)
            }
        } catch (e) {
            setAlert({severity: "error", message: "Invalid fromUrl provided"})
        }

        try {
            setId(parseInt(id))
        } catch (e) {
            setAlert({severity: "error", message: "Invalid Namespace ID Provided"})
        }
    }, [])

    useEffect(() => {
        (async () => {
            if(id !== undefined){
                try {
                    setNamespace(await getNamespace(id))
                } catch (e) {
                    setAlert({severity: "error", message: e as string})
                }
            }
        })()
    }, [id])

    return (
        <AuthenticatedContent redirect={true} boxProps={{width:"100%"}}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={8}>
                    <Collapse in={alert !== undefined}>
                        <Box mb={2}>
                            <Alert severity={alert?.severity}>{alert?.message}</Alert>
                        </Box>
                    </Collapse>
                    {namespace ?
                        <Form
                            namespace={namespace}
                            onSubmit={async (data) => {
                                let namespace = {...data, id: id}
                                setAlert(await submitNamespaceForm(namespace, fromUrl, update))
                            }}
                        /> :
                        <Skeleton variant="rectangular" width="100%" height={400} />
                    }
                </Grid>
                <Grid item lg={4}>
                </Grid>
            </Grid>
        </AuthenticatedContent>
    )
}

export {PutPage};
