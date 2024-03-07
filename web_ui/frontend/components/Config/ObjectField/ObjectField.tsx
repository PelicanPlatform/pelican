import {Box, Button, IconButton, Tooltip, Typography, Modal, Checkbox, FormControlLabel} from "@mui/material";
import React, {ReactElement, useCallback, useMemo} from "react";
import {Edit, Add, KeyboardArrowDown, KeyboardArrowUp, KeyboardDoubleArrowDown, Delete} from "@mui/icons-material";
import {ParameterInputProps} from "@/components/Config/index.d";
import {isEmpty, isEqual, merge} from "lodash";
import {buildPatch} from "@/components/Config/util";
import ObjectModal from "./ObjectModal";
import {ClickAwayListener} from "@mui/base";

interface ListCardProps {
    value: string;
    handleDelete: () => void;
    handleEdit: () => void;
}

const ListCard = ({ value, handleDelete, handleEdit }: ListCardProps) => {

    const [open, setOpen] = React.useState<boolean>(false);

    let confirmDelete = (() => {
        const data = sessionStorage.getItem("confirmDelete");
        return data == "true";
    })()

    const setConfirmDelete = useCallback((value: boolean) => {
        confirmDelete = value
        sessionStorage.setItem("confirmDelete", value.toString())
    }, [])

    return (
        <>
            <Modal open={open} onClose={() => setOpen(false)}>
                <Box
                    sx={{
                        height: "100vh",
                        display: "flex",
                    }}
                >
                    <ClickAwayListener onClickAway={() => setOpen(false)}>
                        <Box
                            sx={{
                                m: "auto",
                                p: 2,
                                bgcolor: "white",
                                borderRadius: 1
                            }}
                        >
                            <Box
                                sx={{
                                    display: "flex",
                                    mb: 2
                                }}
                            >
                                <Box m={"auto"}>
                                    <Typography variant={"h6"}>Confirm Object Deletion</Typography>
                                </Box>
                            </Box>
                            <Box display={"flex"} flexDirection={"column"}>
                                <Box display={"flex"} justifyContent={"space-between"} my={2}>
                                    <Button
                                        variant={"contained"}
                                        onClick={() => {
                                            handleDelete()
                                            setOpen(false)
                                        }}
                                    >
                                        Delete
                                    </Button>
                                    <Button variant={"outlined"} onClick={() => setOpen(false)}>Cancel</Button>
                                </Box>
                                <Box>
                                    <FormControlLabel
                                        sx={{mx: "auto"}}
                                        control={<Checkbox size={"small"} onChange={(e) => setConfirmDelete(e.target.checked)}/>}
                                        label={<Typography variant={"subtitle1"}>Disable Delete Confirmation</Typography>}
                                    />
                                </Box>
                            </Box>
                        </Box>
                    </ClickAwayListener>
                </Box>
            </Modal>
            <Box
                sx={{
                    borderRadius: "4px",
                    marginTop: "0.1rem",
                    padding: "0.1rem 0.5rem",
                    display: "flex",
                    justifyContent: "space-between",
                    cursor: "pointer",
                    borderWidth: "2px",
                    borderStyle: "solid",
                    borderColor: "transparent",
                    "&:hover": {
                        borderColor: "primary.light",
                    }
                }}
            >
                <Box
                    sx={{
                        overflowX: "auto",
                        my: "auto"
                    }}
                >
                    {value}
                </Box>
                <Box>
                    <IconButton size={"small"} onClick={handleEdit}><Edit/></IconButton>
                    <IconButton
                        size={"small"}
                        onClick={() => {
                            if (confirmDelete) {
                                handleDelete()
                            } else {
                                setOpen(true)
                            }
                        }}
                    >
                        <Delete/>
                    </IconButton>
                </Box>
            </Box>
        </>
    )
}

interface ObjectCardProps {
    name: string;
    onClick: () => void;
    updated: boolean;
}

const ObjectCard = ({ name, updated, onClick }: ObjectCardProps) => {
    return (
        <Box
            sx={{
                borderRadius: "4px",
                marginTop: "0.1rem",
                padding: "0.1rem 0.5rem",
                display: "flex",
                justifyContent: "space-between",
                cursor: "pointer",
                borderWidth: updated ? "2px" : "1px",
                borderStyle: "solid",
                borderColor: updated ? "primary.main" : "#c4c4c4",
                "&:hover": {
                    borderColor: "black",
                }
            }}
            onClick={onClick}
        >
            <Box
                sx={{
                    display: "flex",
                    color: "#666666",
                    fontSize: "1.2rem",
                    my: "auto",
                    ml: 1
                }}
            >
                {name}
            </Box>
            <IconButton>
                <Add/>
            </IconButton>
        </Box>
    )
}

export interface ModalProps {
    name: string;
    open: boolean;
    handleClose: () => void;
    children: React.ReactNode;
}

export interface FormProps<T> {
    value: T;
    onSubmit: (v: T) => void;
}

export type ObjectFieldProps<T> = {
    name: string;
    // @ts-ignore
    Form: React.JSX<FormProps<T>>;
    value: T[]
    keyGetter: (v: T) => string;
    onChange: (localValue: T[]) => void
}

function ObjectField<T>({name, Form, value, keyGetter, onChange}: ObjectFieldProps<T>){

    const [open, setOpen] = React.useState<boolean>(false);
    const [error, setError] = React.useState<string | undefined>(undefined)
    const [localValue, setLocalValue] = React.useState<T[]>(value || []);
    const [editValue, setEditValue] = React.useState<T | {}>({});
    const [dropdownHeight, setDropdownHeight] = React.useState<string | undefined>("0px")

    const handleChange = useCallback((submittedValue: T) => {

        let newValue = [...localValue]

        // If the editValue is defined, then we are editing an existing value
        // Filter out the old value so the replacement can be added
        if(!isEmpty(editValue)){
            newValue = localValue.filter((v) => keyGetter(v) != keyGetter(editValue as T))

        // Don't allow duplicate values
        } else if(localValue.some((v) => keyGetter(v) == keyGetter(submittedValue))){
            setError("Tried to add duplicate value")
            setTimeout(() => setError(undefined), 3000)
            return
        }

        newValue = [...newValue, submittedValue]
        setLocalValue(newValue);
        onChange(newValue)

    }, [localValue, onChange, editValue])

    const sortedValue = useMemo(() => {
        const valueArray = structuredClone(localValue)
        valueArray.sort((a, b) => keyGetter(a).localeCompare(keyGetter(b)))
        return valueArray
    }, [localValue])

    const updated = useMemo(() => {
        console.log(value, localValue)
        return !isEqual(value, localValue)
    }, [sortedValue])

    return (
        <>
            <Box>
                <ObjectCard
                    name={name}
                    onClick={() => {
                        setEditValue({})
                        setOpen(true)
                    }}
                    updated={updated}
                />
            </Box>
            <Box>
                <ObjectModal name={name} open={open} handleClose={() => setOpen(false)}>
                    <Form
                        onSubmit={(v: T) => {
                            handleChange(v)
                            setOpen(false)
                        }}
                        value={editValue}
                    />
                </ObjectModal>
                {error && <Typography variant={"subtitle2"} color={"error"}>{error}</Typography>}
            </Box>
            <Box>
                { localValue.length > 0 &&
                    <Box sx={{
                        display: "flex",
                        borderRadius: 1,
                        border: "1px solid #c4c4c4"
                    }}>
                        <Box mx={"auto"}>
                            <Tooltip title={"Minimize"}>
                                <IconButton size="small" onClick={() => setDropdownHeight("0px")}>
                                    <KeyboardArrowUp/>
                                </IconButton>
                            </Tooltip>
                            <Tooltip title={"Scroll View"}>
                                <IconButton size="small" onClick={() => setDropdownHeight("10rem")}>
                                    <KeyboardArrowDown/>
                                </IconButton>
                            </Tooltip>
                            <Tooltip title={"Maximize"}>
                                <IconButton size="small" onClick={() => setDropdownHeight("auto")}>
                                    <KeyboardDoubleArrowDown/>
                                </IconButton>
                            </Tooltip>
                            <Box ml={1} display={"inline"}>
                                <Typography variant={"caption"}>{localValue.length} Items</Typography>
                            </Box>
                        </Box>
                    </Box>
                }
                <Box sx={{
                    maxHeight: dropdownHeight,
                    overflowY: "scroll",
                    borderBottom: localValue.length == 0 || dropdownHeight == "0px" ? undefined : "black 1px solid",
                }}>
                    {
                        sortedValue.map((val) => {
                            return (
                                <ListCard
                                    key={keyGetter(val)}
                                    value={keyGetter(val)}
                                    handleDelete={() => {
                                        const newValue = localValue.filter((v) => keyGetter(v) != keyGetter(val))
                                        setLocalValue(newValue)
                                        onChange(newValue)
                                    }}
                                    handleEdit={() => {
                                        setEditValue(val)
                                        setOpen(true)
                                    }}
                                />
                            )
                        })
                    }
                </Box>
            </Box>
        </>
    )
}

export default ObjectField;
