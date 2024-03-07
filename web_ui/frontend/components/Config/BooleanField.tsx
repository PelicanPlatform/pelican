import {FormControl, InputLabel, MenuItem, Select, SelectChangeEvent} from "@mui/material";
import React, {useMemo, useCallback} from "react";

import { ParameterInputProps } from "@/components/Config/index.d";
import { createId, buildPatch } from "./util";

export type BooleanFieldProps = {
    name: string;
    value: boolean;
    onChange: (value: boolean) => void;
}

const BooleanField = ({onChange, name, value}: BooleanFieldProps) => {

    const id = useMemo(() => createId(name), [name])
    const labelId = useMemo(() => `${id}-label`, [id])

    const [localValue, setLocalValue] = React.useState<boolean>(value);

    const handleOnChange = useCallback((event: SelectChangeEvent<number>) => {
        const v = event.target.value === 1
        setLocalValue(v)
        onChange(v)
    }, [onChange])

    return  (
        <FormControl
            fullWidth
            focused={localValue != value}
        >
            <InputLabel id={labelId}>{name}</InputLabel>
            <Select
                size="small"
                labelId={labelId}
                id={id}
                label={name}
                value={localValue ? 1 : 0}
                onChange={handleOnChange}
            >
                <MenuItem value={1}>True</MenuItem>
                <MenuItem value={0}>False</MenuItem>
            </Select>
        </FormControl>
    )
}

export default BooleanField;
