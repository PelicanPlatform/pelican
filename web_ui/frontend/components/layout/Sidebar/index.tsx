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


import {Box} from "@mui/material";

import styles from "../../../app/page.module.css"
import React, {ReactNode} from "react";

import UserMenu from "./UserMenu";
import {default as NextLink} from "next/link";
import Image from "next/image";
import PelicanLogo from "@/public/static/images/PelicanPlatformLogo_Icon.png";
import AboutMenu from "./AboutMenu";

export const Sidebar = ({children}: {children: ReactNode}) => {

    return (
        <Box>
            <Box sx={{
                display: "flex",
                flexDirection: "row",
                top:0,
                position:"fixed",
                zIndex:2
            }}>
                <Box height={"100vh"} display={"flex"}>
                    <Box className={styles.header} style={{display: "flex", flexDirection: "column", justifyContent:"space-between", padding:"1rem", flexGrow: 1}}>
                        <Box style={{display:"flex", flexDirection: "column"}}>
                            <NextLink href={"/"}>
                                <Image
                                    src={PelicanLogo}
                                    alt={"Pelican Logo"}
                                    width={36}
                                    height={36}
                                    priority={true}
                                    loading={"eager"}
                                />
                            </NextLink>
                            {children}
                        </Box>
                        <Box display={"flex"} flexDirection={"column"} justifyContent={"center"} textAlign={"center"}>
                            <Box pb={1}>
                                <UserMenu/>
                            </Box>
                            <AboutMenu/>
                        </Box>
                    </Box>
                </Box>
            </Box>
        </Box>

    )
}

export default Sidebar;
