import {TextField} from "@mui/material";
import React from "react";

import type {CustomRegistrationFieldProps} from "./index.d";

const validator = (value: string) => {
    if (value && isNaN(Number(value))) {
        return "Value must be a number";
    }
    return undefined;
}

const IntegerField = ({onChange, displayed_name, name, required, description, value}: CustomRegistrationFieldProps<number>) => {

    const [error, setError] = React.useState<string | undefined>(undefined)

    // Check that the value is a number or undefined throwing error if not
    const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const value = event.target.value;

        if (value === "") {
            onChange(null);
            setError(undefined);
        } else if (value && isNaN(Number(value))) {
            setError("Value must be a number");
        } else {
            onChange(parseInt(value));
            setError(undefined);
        }
    }

    return <TextField
        fullWidth
        required={required}
        size="small"
        label={displayed_name}
        name={name}
        variant={"outlined"}
        onChange={handleChange}
        value={value == undefined ? "" : value.toString()}
        error={error !== undefined}
        helperText={error || description}
    />
}

export default IntegerField;
export {IntegerField};
