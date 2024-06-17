import {
    Box,
    Button,
    Alert
} from "@mui/material";
import React, {useEffect, useState, Dispatch, SetStateAction} from "react";
import useSWR from "swr";

import {Namespace} from "@/index";
import CustomRegistrationField from "@/app/registry/components/CustomRegistrationField/index";
import {calculateKeys, deleteKey, getValue, populateKey, submitNamespaceForm} from "@/app/registry/components/util";
import {CustomRegistrationPropsEnum} from "./CustomRegistrationField/index.d";
import {getErrorMessage} from "@/helpers/util";

interface FormProps {
    namespace?: Namespace;
    onSubmit: (data: Partial<Namespace>) => Promise<void>;
}

const getRegistrationFields = async (): Promise<CustomRegistrationPropsEnum[]> => {
    const response = await fetch("/api/v1.0/registry_ui/namespaces", {
        method: "OPTIONS"
    })
    if (response.ok) {
        return await response.json()
    } else {
        throw new Error(await getErrorMessage(response))
    }
}

const onChange = (
    name: string,
    value: string | number | boolean | null,
    setData: Dispatch<SetStateAction<Partial<Namespace | undefined>>>
) => {
    setData((prevData) => {
        // If the value is undefined delete this key from the data dictionary
        if (value === undefined) {
            let newData = structuredClone(prevData)
            deleteKey(newData, calculateKeys(name))
            return newData
        }

        // Otherwise populate the key in the data dictionary
        let newData = structuredClone(prevData)
        populateKey(newData, calculateKeys(name), value)
        return newData
    })
}

const Form = ({
                       namespace,
                       onSubmit
                   }: FormProps) => {

    const [data, setData] = useState<Partial<Namespace> | undefined>(namespace || {})

    const {data: fields, error} = useSWR<CustomRegistrationPropsEnum[]>(
        "getRegistrationFields",
        getRegistrationFields,
        {fallbackData: []}
    )

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault()

                if (!data) {
                    return
                }
                onSubmit(data)
            }}
        >
            {error && <Alert severity={"error"}>{error.message}; Retry is automatic.</Alert>}
            {fields && fields.map((field, index) => {
                return <Box key={field.name} pt={index == 0 ? 0 : 2}>

                    <CustomRegistrationField
                        onChange={(value: string | number | boolean | null) => onChange(field.name, value, setData)}
                        value={getValue(data, calculateKeys(field.name))}
                        {...field}
                    />
                </Box>
            })}
            <Box pt={2}>
                <Button type={"submit"} variant={"contained"}>Submit</Button>
            </Box>
        </form>
    )
}

export default Form
