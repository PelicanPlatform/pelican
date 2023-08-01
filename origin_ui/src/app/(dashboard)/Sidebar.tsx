import Image from 'next/image'
import styles from "../../app/page.module.css"
import {Poppins} from "next/font/google";

import PelicanLogo from "../../public/static/images/PelicanPlatformLogo_Icon.png"
import GithubIcon from "../../public/static/images/github-mark.png"
import {Typography} from "@mui/material";

export const Sidebar = () => {

    return (
        <div className={styles.header} style={{display: "flex", flexDirection: "column", justifyContent:"space-between", padding:"1rem", top:0, position:"sticky", zIndex:"1", overflow: "hidden", height: "100vh"}}>
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
    )
}