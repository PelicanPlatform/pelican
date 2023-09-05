import {Box} from "@mui/material";

import {Header} from "@/components/layout/Header";
import {Sidebar} from "@/app/(dashboard)/Sidebar";

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
        <Box display={"flex"} flexDirection={"row"}>
            <Sidebar/>
            <Box component={"main"} p={2} display={"flex"} minHeight={"100vh"} flexGrow={1}>
                {children}
            </Box>
        </Box>
    )
}
