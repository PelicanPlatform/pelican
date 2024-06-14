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
    Collapse,
    Alert, Skeleton
} from "@mui/material";
import React, {useEffect, useState} from "react";

import {Alert as AlertType, Namespace} from "@/index";
import Form from "@/app/registry/components/Form";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import {submitNamespaceForm} from "@/app/registry/components/util";
import type {NamespaceFormPage} from "./CustomRegistrationField/index.d";


const PostPage = ({update}: NamespaceFormPage) => {

    const [fromUrl, setFromUrl] = useState<URL | undefined>(undefined)
    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

    useEffect(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const fromUrl = urlParams.get('fromUrl')

        try {
            if (fromUrl != undefined) {
                const parsedUrl = new URL(fromUrl)
                setFromUrl(parsedUrl)
            }
        } catch (e) {
            setAlert({severity: "error", message: "Invalid fromUrl provided"})
        }
    }, [])

    return (
        <AuthenticatedContent redirect={true} boxProps={{width:"100%"}}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={7} justifyContent={"space-between"}>
                    <Collapse in={alert !== undefined}>
                        <Box mb={2}>
                            <Alert severity={alert?.severity}>{alert?.message}</Alert>
                        </Box>
                    </Collapse>
                    <Form
                        onSubmit={async (data) => {
                            setAlert(await submitNamespaceForm(data, fromUrl, update))
                        }}
                    />
                </Grid>
                <Grid item lg={2}>
                </Grid>
            </Grid>
        </AuthenticatedContent>
    )
}

export {PostPage}
