import {Action, CustomRegistrationField, FieldType, Option} from "@/components/Config/index.d";
import React from "react";
import {Box, Button} from "@mui/material";

import {FormProps} from "@/components/Config/ObjectField/ObjectField";
import {StringField, SelectField, BooleanField} from "@/components/Config";
import {ObjectField, OptionForm} from "@/components/Config/ObjectField";

const verifyForm = (x: CustomRegistrationField) => {
    return (
        x.name != "" &&
        x.type as string != "" &&
        x.description != "" &&
        x.validationurl != "" &&
        (x.type != "enum" || x.optionurl != "" || ( x.options && x.options.length > 0 ))
    )
}

const CustomRegistrationFieldForm = ({ onSubmit, value }: FormProps<CustomRegistrationField>) => {

    const [name, setName] = React.useState<string>(value?.name || "")
    const [type, setType] = React.useState<FieldType>(value?.type || "")
    const [required, setRequired] = React.useState<boolean>(value?.required || false)
    const [options, setOptions] = React.useState<Option[]>(value?.options || [])
    const [description, setDescription] = React.useState<string>(value?.description || "")
    const [validationUrl, setValidationUrl] = React.useState<string>(value?.validationurl || "")
    const [optionUrl, setOptionUrl] = React.useState<string>(value?.optionurl || "")

    const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const value = {
            type: type,
            name: name,
            required: required,
            options: options,
            description: description,
            validationUrl: validationUrl,
            optionUrl: optionUrl
        }

        if(!verifyForm(value)) {
            return
        }

        onSubmit(value);
    }

    return (
        <form onSubmit={submitHandler}>
            <Box my={2}>
                <StringField onChange={setName} name={"Name"} value={name} />
            </Box>
            <Box mb={2}>
                <SelectField onChange={setType} name={"Type"} value={type} possibleValues={["string", "int", "bool", "datetime", "enum"]}/>
            </Box>
            <Box mb={2}>
                <StringField onChange={setDescription} name={"Description"} value={description} />
            </Box>
            <Box mb={2}>
                <BooleanField onChange={setRequired} name={"Required"} value={required} />
            </Box>
            <Box mb={2}>
                <StringField onChange={setValidationUrl} name={"Validation URL"} value={validationUrl} />
            </Box>
            {type === "enum" &&
                <Box mb={2}>
                    <StringField onChange={setOptionUrl} name={"Option URL"} value={optionUrl} />
                </Box>
            }
            {type === "enum" &&
                <Box mb={2}>
                    <ObjectField onChange={setOptions} name={"Options"} value={options} Form={OptionForm} keyGetter={(x) => x.id}/>
                </Box>
            }
            <Button type={"submit"}>Submit</Button>
        </form>
    )
}

export default CustomRegistrationFieldForm;
