import {FormControl, InputLabel, MenuItem, Select, TextField} from "@mui/material";
import React, {useMemo, useCallback, SetStateAction, ChangeEvent} from "react";

import { ParameterInputProps } from "@/components/Config/index.d";
import { createId, buildPatch } from "./util";

/**
 * Verify if the Integer is in the correct format
 * @param value
 */
const verifyInteger = (value: string): boolean => {

    const regex = new RegExp("^[0-9]+$")
    return regex.test(value)
}

export type IntegerFieldProps = {
    name: string
    value: number;
    onChange: (x: number) => void
}

const IntegerField = ({onChange, name, value}: IntegerFieldProps) => {

    const id = useMemo(() => createId(name), [name])
    const valueString = useMemo(() => value.toString(), [value])

    const [localValue, setLocalValue] = React.useState<string>(valueString);
    const [error, setError] = React.useState<string | undefined>(undefined)

    const handleOnChange = useCallback((event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {

        setLocalValue(event.target.value)

        if(!verifyInteger(event.target.value)) {
            setError("Value must be a integer")
        } else {
            onChange(parseInt(event.target.value))
            setError(undefined)
        }
    }, [onChange])

    return  (
        <TextField
            fullWidth
            size="small"
            id={id}
            label={name}
            variant={"outlined"}
            focused={localValue != valueString}
            value={localValue}
            onChange={handleOnChange}
            error={error !== undefined}
            helperText={error}
        />
    )
}

export default IntegerField;
