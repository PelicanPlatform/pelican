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
import Link from 'next/link'
import {Typography, Box} from "@mui/material";
import IconButton from "@mui/material/IconButton";
import HomeIcon from '@mui/icons-material/Home';
import BuildIcon from '@mui/icons-material/Build';

import styles from "../../app/page.module.css"
import PelicanLogo from "../../public/static/images/PelicanPlatformLogo_Icon.png"
import GithubIcon from "../../public/static/images/github-mark.png"

export const Sidebar = () => {

    return (
        <Box>
            <div className={styles.header} style={{display: "flex", flexDirection: "column", justifyContent:"space-between", padding:"1rem", top:0, position:"fixed", zIndex:"1", overflow: "hidden", height: "100vh"}}>
                <div style={{display:"flex", flexDirection: "column"}}>
                    <Link href={"/index.html"}>
                        <Image
                            src={PelicanLogo}
                            alt={"Pelican Logo"}
                            width={36}
                            height={36}
                        />
                    </Link>
                    <Box pt={3}>
                        <Link href={"/"}>
                            <IconButton>
                                <HomeIcon/>
                            </IconButton>
                        </Link>
                    </Box>
                    <Box pt={1}>
                        <Link href={"/config/index.html"}>
                            <IconButton>
                                <BuildIcon/>
                            </IconButton>
                        </Link>
                    </Box>
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
