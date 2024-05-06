import {Autocomplete, TextField} from "@mui/material";
import React, {useMemo} from "react";

import type {CustomRegistrationFieldProps} from "./index.d";


const EnumerationField = ({onChange, displayed_name, name, required, description, value, options}: CustomRegistrationFieldProps<string>) => {

    const textValue = useMemo(() => options?.find(option => option.id === value), [value, options])

    return <Autocomplete
        fullWidth
        size="small"
        renderInput={(params) => {
            return <TextField
                {...params}
                required={required}
                helperText={description}
                label={displayed_name}
                variant={"outlined"}
            />
        }}
        onChange={(e, value) => {
            const enumerateId = options?.find(option => option.name === value?.name)?.id
            if(enumerateId) {
                onChange(enumerateId)
            }
        }}
        value={textValue || null}
        options={options || []}
        getOptionLabel={(option) => option.name}
    />

}

export default EnumerationField;
export {EnumerationField};
