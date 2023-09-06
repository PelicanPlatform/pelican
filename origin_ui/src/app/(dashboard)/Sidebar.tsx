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

import Image from 'next/image'
import styles from "../../app/page.module.css"
import {Poppins} from "next/font/google";

import PelicanLogo from "../../public/static/images/PelicanPlatformLogo_Icon.png"
import GithubIcon from "../../public/static/images/github-mark.png"
import {Typography, Box} from "@mui/material";

export const Sidebar = () => {

    return (
        <Box>
            <div className={styles.header} style={{display: "flex", flexDirection: "column", justifyContent:"space-between", padding:"1rem", top:0, position:"relative", zIndex:"1", overflow: "hidden", height: "100vh"}}>
                <div style={{display:"flex"}}>
                    <Image
                        src={PelicanLogo}
                        alt={"Pelican Logo"}
                        width={32}
                        height={32}
                    />
                </div>
                <div>
                    <a href={"https://github.com/PelicanPlatform"}>
                        <Image
                            src={GithubIcon}
                            alt={"Github Mark"}
                            width={32}
                            height={32}
                        />
                    </a>
                </div>
            </div>
        </Box>

    )
}
