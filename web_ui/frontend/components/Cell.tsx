import React, {FunctionComponent, useEffect, useRef, useState} from "react";
import {Button, ButtonProps, TableCell} from "@mui/material";

export const TableCellOverflow: FunctionComponent<any> = ({ children, ...props }) => {

    const cellRef = useRef<HTMLTableCellElement>(null);
    const [overflow, setOverflow] = useState<boolean>(false);

    useEffect(() => {
        if(cellRef.current) {
            setOverflow(cellRef.current.scrollWidth > cellRef.current.clientWidth)
        }
    }, [])

    return (
        <TableCell
            ref={cellRef}
            sx={{
                overflowX: "scroll",
                whiteSpace: "nowrap",
                boxShadow: overflow ? "inset -13px 0px 20px -21px rgba(0,0,0,0.75)" : "none",
                border: "solid #ececec 1px",
                ...props?.sx
            }}>
            {children}
        </TableCell>
    )
}

export const TableCellButton: FunctionComponent<any> = ({ children, ...props } : ButtonProps) => {

        return (
            <TableCell
                sx={{
                    textAlign: "center",
                    border: "solid #ececec 1px",
                    padding: "0px",
                    ...props?.sx
                }}>
                <Button {...props}>
                    {children}
                </Button>
            </TableCell>
        )
}
