import {Box} from "@mui/material";

import {Header} from "@/components/layout/Header";

export const metadata = {
    title: 'Origin Initialization',
    description: 'Software designed to make data distribution easy',
}

export default function RootLayout({
                                       children,
                                   }: {
    children: React.ReactNode
}) {
    return (
        <>
            <Header/>
            <Box component={"main"} pt={"75px"} display={"flex"} minHeight={"100vh"}>
                {children}
            </Box>
        </>
    )
}
