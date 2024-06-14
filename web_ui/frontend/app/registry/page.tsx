/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

import {PendingCard, Card, CardSkeleton, CreateNamespaceCard, NamespaceCardList} from "@/components";
import Link from "next/link";
import {Namespace, Alert as AlertType} from "@/index";
import {getUser} from "@/helpers/login";
import {Add} from "@mui/icons-material";
import useSWR from "swr";
import {CardProps} from "@/components/Namespace/Card";
import {PendingCardProps} from "@/components/Namespace/PendingCard";


export default function Home() {

    const [data, setData] = useState<{namespace: Namespace}[] | undefined>(undefined);
    const [alert, setAlert] = useState<AlertType | undefined>(undefined)

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

    const _setData = async () => {setData(await getData())}

    useEffect(() => {
        _setData();
    }, [])

    const {data: user, error} = useSWR("getUser", getUser)

    const pendingData = useMemo(() => {
        return data?.filter(
                ({namespace}) => namespace.admin_metadata.status === "Pending" &&
                    (user?.user == namespace.admin_metadata.user_id || user?.role == "admin")
            )
        }, [data, user]
    )
    const approvedOriginData = useMemo(
        () => data?.filter(
            ({namespace}) => namespace.admin_metadata.status === "Approved" && namespace.type == "origin"
        ),
        [data]
    )
    const approvedCacheData = useMemo(
        () => data?.filter(
            ({namespace}) => namespace.admin_metadata.status === "Approved" && namespace.type == "cache"
        ),
        [data]
    )
    const approvedNamespaceData = useMemo(
        () => data?.filter(
            ({namespace}) => namespace.admin_metadata.status === "Approved" && namespace.type == "namespace"
        ),
        [data]
    )

    return (
        <Box width={"100%"}>
            <Grid container spacing={2}>
                <Grid item xs={12} lg={6} xl={5}>
                    <Typography variant={"h4"}>Namespace Registry</Typography>
                    <Collapse in={alert !== undefined}>
                        <Box mt={2}>
                            <Alert severity={alert?.severity}>{alert?.message}</Alert>
                        </Box>
                    </Collapse>
                </Grid>
                <Grid item xs={12} lg={8} justifyContent={"space-between"}>
                    { user == undefined || !user.authenticated &&
                        <Alert severity="info">
                            <Typography variant={"body1"}>
                                Login to register new namespaces.
                                <Link href={"/login/?returnURL=/view/registry"}>
                                    <Button sx={{ml:2}} variant={"contained"} size={"small"} color={"primary"}>Login</Button>
                                </Link>
                            </Typography>
                        </Alert>
                    }
                    {
                        pendingData && pendingData.length > 0 &&
                        <Grid item xs={12}>
                            <Paper sx={{p:2, borderColor: "primary.main", borderWidth: "3px", borderType: "solid"}} elevation={3}>
                                <Typography variant={"h5"} pb={2}>Pending Registrations</Typography>
                                <Typography variant={"subtitle1"} pb={2}>
                                    {user !== undefined && user?.role == "admin" && "Awaiting approval from you."}
                                    {user !== undefined && user?.role != "admin" && "Awaiting approval from registry administrators."}
                                </Typography>
                                <NamespaceCardList<PendingCardProps> data={pendingData} Card={PendingCard} cardProps={{authenticated:user, onAlert: (a: AlertType) => setAlert(a), onUpdate:_setData}}/>
                            </Paper>
                        </Grid>
                    }

                    <Typography variant={"h5"} py={2} pt={4}>Approved Registrations</Typography>

                    <Typography variant={"subtitle1"}>
                        {user !== undefined && user?.role == "admin" &&
                            "As an administrator, you can edit Approved Registrations by clicking the pencil button."
                        }
                        {user !== undefined && user?.role != "admin" &&
                            "To edit an Approved Registration you own, please contact the registry administrators."
                        }
                    </Typography>

                    <Typography variant={"h6"} py={2}>
                        Namespaces
                        { approvedCacheData !== undefined &&
                            <Link href={"namespace/register"}>
                                <IconButton sx={{ml: .5, mb: .5}} size={"small"}>
                                    <Add/>
                                </IconButton>
                            </Link>
                        }
                    </Typography>
                    { approvedNamespaceData !== undefined && approvedNamespaceData.length > 0 && <NamespaceCardList<CardProps> data={approvedNamespaceData} Card={Card} cardProps={{authenticated: user}} /> }
                    { approvedNamespaceData !== undefined && approvedNamespaceData.length === 0 && <CreateNamespaceCard text={"Register Namespace"} url={"namespace/register"}/>}

                    <Typography variant={"h6"} py={2}>
                        Origins
                        { approvedOriginData !== undefined &&
                            <Link href={"origin/register"}>
                                <IconButton sx={{ml: .5, mb: .5}} size={"small"}>
                                    <Add/>
                                </IconButton>
                            </Link>
                        }
                    </Typography>
                    { approvedOriginData !== undefined && approvedOriginData.length > 0 && <NamespaceCardList<CardProps> data={approvedOriginData} Card={Card} cardProps={{authenticated: user}} /> }
                    { approvedOriginData !== undefined && approvedOriginData.length === 0 && <CreateNamespaceCard text={"Register Origin"} url={"origin/register"}/>}

                    <Typography variant={"h6"} py={2}>
                        Caches
                        { approvedCacheData !== undefined &&
                            <Link href={"cache/register"}>
                                <IconButton sx={{ml: .5, mb: .5}} size={"small"}>
                                    <Add/>
                                </IconButton>
                            </Link>
                        }
                    </Typography>
                    { approvedCacheData !== undefined && approvedCacheData.length > 0 && <NamespaceCardList<CardProps> data={approvedCacheData} Card={Card} cardProps={{authenticated: user}} /> }
                    { approvedCacheData !== undefined && approvedCacheData.length === 0 && <CreateNamespaceCard text={"Register Cache"} url={"cache/register"}/>}

                </Grid>
                <Grid item lg={6} xl={8}>
                </Grid>
            </Grid>
        </Box>
    )
}
