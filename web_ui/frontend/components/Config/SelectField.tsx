import {FormControl, InputLabel, MenuItem, Select, SelectChangeEvent, TextField} from "@mui/material";
import React, {useMemo, useCallback, SetStateAction, ChangeEvent} from "react";

import { ParameterInputProps } from "@/components/Config/index.d";
import { createId, buildPatch } from "./util";
import OutlinedInput from "@mui/material/OutlinedInput";


export type SelectFieldProps<T extends string> = {
    name: string
    value: T;
    onChange: (x: T) => void;
    possibleValues: T[];
}

function SelectField<T extends string>({onChange, name, value, possibleValues}: SelectFieldProps<T>){

    const id = useMemo(() => createId(name), [name])

    const [localValue, setLocalValue] = React.useState<T>(value);

    const handleChange = (event: SelectChangeEvent<T>) => {
        const {
            target: { value },
        } = event;

        setLocalValue(value as T);
        onChange(value as T)
    };

    return (
        <div>
            <FormControl
                size={"small"}
                focused={value != localValue}
                fullWidth
            >
                <InputLabel id={`${id}-label`}>{name}</InputLabel>
                <Select<T>
                    labelId={`${id}-label`}
                    id={id}
                    value={localValue}
                    onChange={handleChange}
                    input={<OutlinedInput label="Name" />}
                >
                    {possibleValues.map((v) => (
                        <MenuItem
                            key={v}
                            value={v}
                        >
                            {v}
                        </MenuItem>
                    ))}
                </Select>
            </FormControl>
        </div>
    )
}

export default SelectField;
