import {Server, StringTree} from "@/index";
import {Dropdown, InformationSpan} from "@/components";
import {Box, Typography} from "@mui/material";
import DirectoryTree from "@/components/DirectoryTree";
import React from "react";

interface DirectorDropdownProps {
    server: Server;
    transition: boolean;
}

export const DirectorDropdown = ({server, transition} : DirectorDropdownProps) => {
    return (
        <Dropdown transition={transition} flexDirection={"column"}>
            <InformationSpan name={"Type"} value={server.type} />
            <InformationSpan name={"Status"} value={server.status} />
            <InformationSpan name={"URL"} value={server.url} />
            <Typography variant={"body2"} sx={{fontWeight: 500,  display: "inline", mr: 2, my: .5}}>Namespace Prefixes</Typography>
            <DirectoryTree data={directoryListToTree(server.namespacePrefixes)} />
        </Dropdown>
    )
}

const directoryListToTree = (directoryList: string[]): StringTree => {
    let tree = {};
    directoryList.forEach((directory) => {
        const path = directory.split("/").filter((x) => x != "").map((x) => "/" + x);
        tree = directoryListToTreeHelper(path, tree);
    })

    return tree;
}

const directoryListToTreeHelper = (path: string[], tree: StringTree): true | StringTree => {

    if (path.length == 0) {
        return true
    }

    if (!tree[path[0]] || tree[path[0]] === true) {
        tree[path[0]] = {}
    }

    tree[path[0]] = directoryListToTreeHelper(path.slice(1), tree[path[0]])

    return tree
}
