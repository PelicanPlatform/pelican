import {Path} from "@/components/Config/index.d";
import React from "react";
import {Box, Button} from "@mui/material";

import {FormProps} from "@/components/Config/ObjectField/ObjectField";
import {StringField, BooleanField} from "@/components/Config";

const verifyForm = (x: Path) => {
    return x.path != ""
}

const PathForm = ({ onSubmit, value }: FormProps<Path>) => {

    const [path, setPath] = React.useState<string>(value?.path || "")
    const [recursive, setRecursive] = React.useState<boolean>(value?.recursive || false)

    const submitHandler = () => {
        const pathObject = {
            path: path,
            recursive: recursive
        }

        if(!verifyForm(pathObject)) {
            return
        }

        onSubmit(pathObject);
    }

    return (
        <>
            <Box my={2}>
                <StringField onChange={setPath} name={"Path"} value={path} />
            </Box>
            <Box mb={2}>
                <BooleanField onChange={setRecursive} name={"Name"} value={recursive} />
            </Box>
            <Button onClick={submitHandler}>Submit</Button>
        </>
    )
}

export default PathForm;
