import {Institution} from "@/components/Config/index.d";
import React from "react";
import {Box, Button, TextField} from "@mui/material";

import {FormProps, ModalProps} from "@/components/Config/ObjectField/ObjectField";
const InstitutionForm = ({ onSubmit, value }: FormProps<Institution>) => {

    const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const form = event.currentTarget as HTMLFormElement;
        const formData = new FormData(form);
        const institution = {
            id: formData.get("id") as string,
            name: formData.get("name") as string
        }
        onSubmit(institution);
    }

    return (
        <form onSubmit={submitHandler}>
            <Box my={2}>
                <TextField
                    fullWidth
                    size="small"
                    id={"name"}
                    name={"name"}
                    label={"Name"}
                    variant={"outlined"}
                    defaultValue={value?.name}
                />
            </Box>
            <Box mb={2}>
                <TextField
                    fullWidth
                    size="small"
                    id={"id"}
                    name={"id"}
                    label={"ID"}
                    variant={"outlined"}
                    defaultValue={value?.id}
                />
            </Box>
            <Button type={"submit"}>Submit</Button>
        </form>
    )
}

export default InstitutionForm;
