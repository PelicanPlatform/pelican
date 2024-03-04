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
import Image from "next/image";
import {Add, Build, TripOrigin, Storage} from "@mui/icons-material";

import {Sidebar} from "@/components/layout/Sidebar";
import PelicanLogo from "@/public/static/images/PelicanPlatformLogo_Icon.png";
import IconButton from "@mui/material/IconButton";
import {Main} from "@/components/layout/Main"
import SpeedDial, {SpeedButtonControlledProps} from "@/components/layout/SidebarSpeedDial";

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
                <Link href={"/registry/"}>
                    <Image
                        src={PelicanLogo}
                        alt={"Pelican Logo"}
                        width={36}
                        height={36}
                    />
                </Link>
                <Box pt={1}>
                    <SpeedDial actions={actions}/>
                </Box>
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
