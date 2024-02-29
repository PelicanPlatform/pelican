import {FormControl, InputLabel, MenuItem, Select, FormHelperText} from "@mui/material";
import React, {useEffect, useState} from "react";

import {Institution} from "@/components/Main";

const getInstitutionById = (id: string, institutions: Institution[]) => {
    return institutions.filter((i) => i.id === id)[0]
}

interface InstitutionFieldsProps {
    inputInstitution?: string;
}

const InstitutionField = ({inputInstitution} : InstitutionFieldsProps) => {

    const [error, setError] = useState<boolean>(false)
    const [institutionId, setInstitutionId] = useState<string | undefined>(inputInstitution)
    const [institutions, setInstitutions] = useState<Institution[]>([])

    useEffect(() => {
        (async () => {
            const url = new URL("/api/v1.0/registry_ui/institutions", window.location.origin)
            const response = await fetch(url)
            if (response.ok) {
                const responseData: Institution[] = await response.json()

                if(responseData.length === 0) {
                    setError(true)
                }

                setInstitutions(responseData)
            } else {
                setError(true)
            }
        })()
    }, []);

    return (
        <FormControl
            required
            fullWidth
            size={"small"}
            error={error}
        >
            <InputLabel id="institution-label">Institution</InputLabel>
            <Select
                labelId="institution-label"
                id="institution"
                name={"institution"}
                label="Institution *"
                value={institutionId}
                onChange={event => setInstitutionId(event.target.value as string)}
            >
                {institutions.map(institution => <MenuItem key={institution.id}
                                                           value={institution.id}>{institution.name}</MenuItem>)}
            </Select>
            { error && <FormHelperText>No Institutions Provided, Contact Administrator</FormHelperText> }
        </FormControl>
    )
}

export default InstitutionField;
