import {Action, Lot, Path} from "@/components/Config/index.d";
import React from "react";
import {Box, Button} from "@mui/material";

import {FormProps} from "@/components/Config/ObjectField/ObjectField";
import {StringField, IntegerField, DateTimeField} from "@/components/Config";
import {ObjectField} from "@/components/Config/ObjectField";
import PathForm from "@/components/Config/ObjectField/PathForm";

const verifyForm = (x: Lot) => {
    return (
        x.lotname != "" &&
        x.owner != "" &&
        x.managementpolicyattrs.creationtime.value != 0 &&
        x.managementpolicyattrs.expirationtime.value != 0 &&
        x.managementpolicyattrs.deletiontime.value != 0
    )
}

const LotForm = ({ onSubmit, value }: FormProps<Lot>) => {

    const [lotName, setLotName] = React.useState<string>(value?.lotname || "")
    const [owner, setOwner] = React.useState<string>(value?.owner || "")
    const [paths, setPaths] = React.useState<Path[]>(value?.paths || [])
    const [dedicatedGB, setDedicatedGB] = React.useState<number>(value?.managementpolicyattrs?.dedicatedgb || 0)
    const [opportunisticGB, setOpportunisticGB] = React.useState<number>(value?.managementpolicyattrs?.opportunisticgb || 0)
    const [maxNumberObjects, setMaxNumberObjects] = React.useState<number>(value?.managementpolicyattrs?.maxnumberobjects.value || 0)
    const [creationTime, setCreationTime] = React.useState<number>(value?.managementpolicyattrs?.creationtime?.value || 0)
    const [expirationTime, setExpirationTime] = React.useState<number>(value?.managementpolicyattrs?.expirationtime?.value || 0)
    const [deletionTime, setDeletionTime] = React.useState<number>(value?.managementpolicyattrs?.deletiontime?.value || 0)

    const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const value = {
            lotname: lotName,
            owner: owner,
            paths: paths,
            managementpolicyattrs: {
                dedicatedgb: dedicatedGB,
                opportunisticgb: opportunisticGB,
                maxnumberobjects: {
                    value: maxNumberObjects
                },
                creationtime: {
                    value: creationTime
                },
                expirationtime: {
                    value: expirationTime
                },
                deletiontime: {
                    value: deletionTime
                }
            }
        }

        if(!verifyForm(value)) {
            return
        }

        onSubmit(value);
    }

    return (
        <form onSubmit={submitHandler}>
            <Box my={2}>
                <StringField onChange={setLotName} name={"LotName"} value={lotName} />
            </Box>
            <Box mb={2}>
                <StringField onChange={setOwner} name={"Owner"} value={owner} />
            </Box>
            <Box mb={2}>
                <ObjectField onChange={setPaths} name={"Paths"} value={paths} Form={PathForm} keyGetter={(x) => x.path}/>
            </Box>
            <Box mb={2}>
                <IntegerField onChange={setDedicatedGB} name={"DedicatedGB"} value={dedicatedGB} />
            </Box>
            <Box mb={2}>
                <IntegerField onChange={setOpportunisticGB} name={"OpportunisticGB"} value={opportunisticGB} />
            </Box>
            <Box mb={2}>
                <IntegerField onChange={setMaxNumberObjects} name={"MaxNumObjects"} value={maxNumberObjects} />
            </Box>
            <Box mb={2}>
                <DateTimeField onChange={setCreationTime} name={"CreationTime"} value={creationTime} />
            </Box>
            <Box mb={2}>
                <DateTimeField onChange={setExpirationTime} name={"ExpirationTime"} value={expirationTime} />
            </Box>
            <Box mb={2}>
                <DateTimeField onChange={setDeletionTime} name={"DeletionTime"} value={deletionTime} />
            </Box>
            <Button type={"submit"}>Submit</Button>
        </form>
    )
}

export default LotForm;
