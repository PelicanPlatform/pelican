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
    Alert, Skeleton
} from "@mui/material";
import React, {ReactNode, Suspense, useEffect, useMemo, useState} from "react";

import {Alert as AlertType, Namespace} from "@/components/Main";
import Form from "@/app/registry/components/Form";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import {submitNamespaceForm, namespaceToCache, postGeneralNamespace} from "@/app/registry/components/util";
import type {NamespaceFormPage} from "./CustomRegistrationField/index.d";


const PostPage = ({update}: NamespaceFormPage) => {

    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

    return (
        <AuthenticatedContent redirect={true} boxProps={{width:"100%"}}>
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
                    <Suspense fallback={<Skeleton variant="rectangular" width="100%" height={400} />}>
                        <Form
                            onSubmit={async (data) => {
                                setAlert(await submitNamespaceForm(data, update))
                            }}
                        />
                    </Suspense>
                </Grid>
                <Grid item lg={2}>
                </Grid>
            </Grid>
        </AuthenticatedContent>
    )
}

export {PostPage}
