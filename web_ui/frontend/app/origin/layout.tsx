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
import {Build, Dashboard, Public} from "@mui/icons-material";
import IconButton from "@mui/material/IconButton";

import Main from "@/components/layout/Main";
import {Sidebar} from "@/components/layout/Sidebar";

export const metadata = {
    title: 'Pelican Origin',
    description: 'Software designed to make data distribution easy',
}

export default function RootLayout({
                                       children,
                                   }: {
    children: React.ReactNode
}) {
    return (
        <Box display={"flex"} flexDirection={"row"}>
            <Sidebar>
                {
                    true &&
                    <>
                    <Box pt={1}>
                        <Tooltip title={"Dashboard"} placement={"right"}>
                            <Link href={"/origin/"}>
                                <IconButton>
                                    <Dashboard/>
                                </IconButton>
                            </Link>
                        </Tooltip>
                    </Box>
                    <Box pt={1}>
                        <Tooltip title={"Globus Configurations"} placement={"right"}>
                            <Link href={"/origin/globus/"}>
                                <IconButton>
                                    <Public/>
                                </IconButton>
                            </Link>
                        </Tooltip>
                    </Box>
                    </>
                }
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
