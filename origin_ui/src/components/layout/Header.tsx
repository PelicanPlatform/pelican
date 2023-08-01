'use client'

import Image from 'next/image'
import {useState, useEffect} from "react";
import styles from "../../app/page.module.css"
import {Poppins} from "next/font/google";

import PelicanLogo from "../../public/static/images/PelicanPlatformLogo_Icon.png"
import GithubIcon from "../../public/static/images/github-mark.png"
import {Typography} from "@mui/material";

export const Header = () => {

    let [scrolledTop, setScrolledTop] = useState(true);

    useEffect(() => {
        setScrolledTop(window.scrollY < 50);
        addEventListener("scroll", (event) => {
            setScrolledTop(window.scrollY < 50);
        });
    }, [] )

    return (
        <div className={`${styles.header} ${scrolledTop ? styles.headerScrolled : ""}`} style={{display: "flex", justifyContent:"space-between", padding:"1rem", position:"fixed", zIndex:"1", width: "100%", overflow: "hidden"}}>
            <div style={{display:"flex"}}>
                <Image
                    src={PelicanLogo}
                    alt={"Pelican Logo"}
                    width={32}
                    height={32}
                />
                <Typography variant={"h5"} my={"auto"} ml={".5rem"}>Pelican Origin</Typography>
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