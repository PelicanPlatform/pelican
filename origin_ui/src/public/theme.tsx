'use client'

import {createTheme, responsiveFontSizes, ThemeProvider} from "@mui/material";
import {FC} from "react";
import {blue} from "@mui/material/colors";
import {Poppins} from "next/font/google";

const poppins = Poppins({
    subsets: ['latin'], style: ['normal'], weight: ['300', '400', '600'], display: 'swap'
})

let theme = createTheme({
    palette: {

        primary: {
            main: "#0885ff",
            light: "#CFE4FF"
        },
        secondary: {
            main: "#FFFFFA"
        }
    },
    typography: {
        h1: {
            fontFamily: poppins.style.fontFamily
        },
        h2: {
            fontFamily: poppins.style.fontFamily
        },
        h3: {
            fontFamily: poppins.style.fontFamily
        },
        h4: {
            fontFamily: poppins.style.fontFamily
        },
        h5: {
            fontFamily: poppins.style.fontFamily
        },
        h6: {
            fontFamily: poppins.style.fontFamily
        },
        body1: {
            fontSize: "1.2rem",
        },
        fontFamily: [
            "Helvetica Neue",
            "Helvetica",
            "Arial",
            "Lucida Grande",
            "sans-serif"
        ].join(",")
    },
    components: {
        MuiContainer: {
            defaultProps: {}
        },
    },
});

theme = responsiveFontSizes(theme, {factor: 3})

interface ThemeProviderClientProps {
    children: React.ReactNode
}

export const ThemeProviderClient: FC<ThemeProviderClientProps> = ({children}) => {
    return <ThemeProvider theme={theme}>{children}</ThemeProvider>
}