import { TreeViewBaseItem } from '@mui/x-tree-view/models';
import { RichTreeView } from '@mui/x-tree-view/RichTreeView';

import type { StringTree } from '@/index';
import {useState} from "react";
import {TreeItem, TreeItemProps} from "@mui/x-tree-view";
import {Typography} from "@mui/material";


export const DirectoryTree = ({ data }: {data: StringTree}) => {

    const [selectedItems, setSelectedItems] = useState<string[]>([]);

    const handleSelect = (ids: string[]) => {
        console.log(ids, calculateSelectedItems(ids[0]))

        setSelectedItems(calculateSelectedItems(ids[0]));
    }

    return (
        <RichTreeView
            multiSelect
            items={dataToTreeViewBaseItem(data)}
            selectedItems={selectedItems}
            onSelectedItemsChange={(e, ids) => handleSelect(ids)}
            slots={{item: CustomTreeItemSmall}}
        />
    );
};

const CustomTreeItemSmall = ({ ...props }: TreeItemProps) => {
    return (
        <TreeItem {...props} label={<Typography variant={"body2"}>{props.label}</Typography>} />
    )
}

const dataToTreeViewBaseItem = (tree: StringTree): TreeViewBaseItem[] => {
    return dataToTreeViewBaseItemHelper(tree, []);
}

const dataToTreeViewBaseItemHelper = (tree: StringTree, parent: string[]): TreeViewBaseItem[] => {
    return Object.entries(tree).map(([name, children]) => {
        let item : TreeViewBaseItem = { id: [...parent, name].join(""), label: name };
        if(children !== true) {
            item.children = dataToTreeViewBaseItemHelper(children, parent.concat(name));
        }
        return item
    });
}

const calculateSelectedItems = (id: string): string[] => {
    const path = id.split("/").filter((x) => x != "")
    const selectedItems: string[] = []
    path.forEach((_, index) => {
        selectedItems.push("/" + path.slice(0, index + 1).join("/"))
    })
    return selectedItems
}

export default DirectoryTree;
