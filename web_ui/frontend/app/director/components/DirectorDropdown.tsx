import { Capabilities, Server, StringTree } from '@/index';
import { CapabilitiesChip, CapabilitiesDisplay, Dropdown, InformationSpan } from '@/components';
import { Box, Grid, Typography } from '@mui/material';
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
            <InformationSpan name={"Status"} value={server.healthStatus} />
            <InformationSpan name={"URL"} value={server.url} />
            <InformationSpan name={"Longitude"} value={server.longitude.toString()} />
            <InformationSpan name={"Latitude"} value={server.latitude.toString()} />
            { server.capabilities &&
              <Box mt={1}>
                <CapabilitiesRow capabilities={server.capabilities} />
              </Box>
            }
            <Box sx={{my: 1}}>
              <Typography variant={"body2"} sx={{fontWeight: 500,  display: "inline", mr: 2 }}>Namespace Prefixes</Typography>
              <DirectoryTree data={directoryListToTree(server.namespacePrefixes)} />
            </Box>
        </Dropdown>
    )
}

const CapabilitiesRow = ({capabilities}: { capabilities: Capabilities }) => {
  return (
      <Grid container spacing={1}>
        {Object.entries(capabilities).map(([key, value]) => {
          return (
            <Grid item md={12/5} sm={12/4} xs={12/2} key={key}>
              <CapabilitiesChip name={key} value={value} />
            </Grid>
          )
        })}
      </Grid>
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
