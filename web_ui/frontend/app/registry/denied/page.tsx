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

import {Box, Button, Grid, Typography, Paper, Alert, Collapse, IconButton} from "@mui/material";
import React, {useEffect, useMemo, useState} from "react";

import {PendingCard, Card, CardSkeleton, CreateNamespaceCard} from "@/components/Namespace";
import Link from "next/link";
import {Namespace, Alert as AlertType} from "@/index";
import {getUser} from "@/helpers/login";
import {Add} from "@mui/icons-material";
import NamespaceCardList from "@/components/Namespace/NamespaceCardList";
import useSWR from "swr";
import {CardProps} from "@/components/Namespace/Card";
import {PendingCardProps} from "@/components/Namespace/PendingCard";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import DeniedCard from "@/components/Namespace/DeniedCard";


const getData = async () => {

    let data: {namespace: Namespace}[] = []

    const url = new URL("/api/v1.0/registry_ui/namespaces", window.location.origin)

    const response = await fetch(url)
    if (response.ok) {
        const responseData: Namespace[] = await response.json()
        responseData.sort((a, b) => a.id > b.id ? 1 : -1)
        responseData.forEach((namespace) => {
            if (namespace.prefix.startsWith("/caches/")) {
                namespace.type = "cache"
                namespace.prefix = namespace.prefix.replace("/caches/", "")
            } else if (namespace.prefix.startsWith("/origins/")) {
                namespace.type = "origin"
                namespace.prefix = namespace.prefix.replace("/origins/", "")
            } else {
                namespace.type = "namespace"
            }
        })

        // Convert data to Partial CardProps
        data = responseData.map((d) => {
            return {namespace: d}
        })
    }

    return data
}

export default function Home() {

    const {data} = useSWR("getNamespaces", getData)
    const {data: user, error} = useSWR("getUser", getUser)

    const deniedNamespaces = useMemo(
        () => data?.filter(
            ({namespace}) => namespace.admin_metadata.status === "Denied"
        ),
        [data]
    )

    return (
        <Box width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={6} xl={5}>
                    <Typography variant={"h4"}>Namespace Registry</Typography>
                    <Collapse in={error !== undefined}>
                        <Box mt={2}>
                            <Alert severity={"error"}>{error?.toString()}</Alert>
                        </Box>
                    </Collapse>
                </Grid>
                <Grid item xs={12} lg={8} justifyContent={"space-between"}>
                    <AuthenticatedContent redirect={true}>
                        <Typography variant={"h6"} py={2}>
                            Denied Namespaces
                        </Typography>
                        { deniedNamespaces !== undefined ? <NamespaceCardList<CardProps> data={deniedNamespaces} Card={DeniedCard} cardProps={{authenticated: user}} /> : <CardSkeleton/> }
                    </AuthenticatedContent>
                </Grid>
                <Grid item lg={6} xl={8}>
                </Grid>
            </Grid>
        </Box>
    )
}
