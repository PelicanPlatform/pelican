import {TextField} from "@mui/material";
import React, {useMemo} from "react";
import {DateTimePicker, LocalizationProvider} from "@mui/x-date-pickers";
import {AdapterLuxon} from "@mui/x-date-pickers/AdapterLuxon";
import FormControl from "@mui/material/FormControl";
import FormHelperText from "@mui/material/FormHelperText";
import {DateTime} from "luxon";

import type { CustomRegistrationFieldProps } from "./index.d";

const EpochTimeField = ({onChange, displayed_name, name, required, description, value}: CustomRegistrationFieldProps<number>) => {

    const dateTime = useMemo(() => {
        if(typeof value === "number") {
            DateTime.fromSeconds(value)
        }
        return undefined
    }, [value])

    return (
        <LocalizationProvider dateAdapter={AdapterLuxon}>
            <FormControl fullWidth>
                <DateTimePicker
                    label={displayed_name}
                    slotProps={{
                        textField: {
                            name: name,
                            required: required,
                            size: "small"
                        },
                    }}
                    value={dateTime && DateTime.fromSeconds(dateTime)}
                    onChange={(newValue: DateTime | null) => {
                        onChange(newValue ? newValue.toUTC().toSeconds() : null)
                    }}
                />
                {description && <FormHelperText>{description}</FormHelperText>}
            </FormControl>
        </LocalizationProvider>
    )
}

export default EpochTimeField;
export {EpochTimeField};