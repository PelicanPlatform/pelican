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


import {Box, Tooltip} from "@mui/material";
import Link from "next/link";
import {Build, FolderOpen, TripOrigin, Storage, Block} from "@mui/icons-material";

import {Sidebar} from "@/components/layout/Sidebar";
import IconButton from "@mui/material/IconButton";
import {Main} from "@/components/layout/Main"
import SpeedDial, {SpeedButtonControlledProps} from "@/components/layout/SidebarSpeedDial";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";

export const metadata = {
    title: 'Pelican Registry',
    description: 'Software designed to make data distribution easy',
}

export default function RootLayout({
                                       children,
                                   }: {
    children: React.ReactNode
}) {

    const actions: SpeedButtonControlledProps[] = [
        {
            href: "/registry/namespace/register/",
            icon: <FolderOpen/>,
            text: "Namespace",
            title: "Register a new Namespace"
        },
        {
            href: "/registry/origin/register/",
            icon: <TripOrigin/>,
            text: "Origin",
            title: "Register a new Origin"
        },
        {
            href: "/registry/cache/register/",
            icon: <Storage/>,
            text: "Cache",
            title: "Register a new Cache"
        }
    ]

    return (
        <Box display={"flex"} flexDirection={"row"}>
            <Sidebar>
                <Box pt={1}>
                    <SpeedDial actions={actions}/>
                </Box>
                <AuthenticatedContent>
                    <Box pt={1}>
                        <Tooltip title={"Denied Namespaces"} placement={"right"}>
                            <Link href={"/registry/denied/"}>
                                <IconButton>
                                    <Block/>
                                </IconButton>
                            </Link>
                        </Tooltip>
                    </Box>
                </AuthenticatedContent>
                <Box pt={1}>
                    <Tooltip title={"Config"} placement={"right"}>
                        <Link href={"/config/"}>
                            <IconButton>
                                <Build/>
                            </IconButton>
                        </Link>
                    </Tooltip>
                </Box>
            </Sidebar>
            <Main>
                {children}
            </Main>
        </Box>
    )
}
