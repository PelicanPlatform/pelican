import {GeoIPOverride, Institution} from "@/components/Config/index.d";
import React from "react";
import {Box, Button, TextField, Typography} from "@mui/material";

import {FormProps, ModalProps} from "@/components/Config/ObjectField/ObjectField";
import {StringField} from "@/components/Config";

const verify = (x: GeoIPOverride) => {

}

const GeoIPOverrideForm = ({ onSubmit, value }: FormProps<GeoIPOverride>) => {

    const [error, setError] = React.useState<string | undefined>(undefined)

    const submitHandler = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const form = event.currentTarget as HTMLFormElement;
        const formData = new FormData(form);
        const value = {
            ip: formData.get("ip") as string,
            coordinate: {
                lat: formData.get("latitude") as string,
                long: formData.get("longitude") as string
            }
        }
        onSubmit(value);
    }

    return (
        <form onSubmit={submitHandler}>
            { error != undefined &&
                <Typography variant={"subtitle2"}>{error}</Typography>
            }
            <Box my={2}>
                <StringField
                    onChange={() => {}}
                    name={"IP"}
                    value={value?.ip}
                    verify={(x: string) => {
                        const isValid = /^(?:(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(?!$)|$)){4}$/.test(x)
                        return isValid ? undefined : "Invalid IP Address"
                    }}
                />
            </Box>
            <Box mb={2}>
                <StringField
                    onChange={() => {}}
                    name={"Latitude"}
                    value={value?.coordinate?.lat}
                    verify={(x: string) => {
                        const isValid = /^(\+|-)?(?:90(?:(?:\.0{1,6})?)|(?:[0-9]|[1-8][0-9])(?:(?:\.[0-9]{1,6})?))$/.test(x)
                        return isValid ? undefined : "Invalid Latitude"
                    }}
                />
            </Box>
            <Box mb={2}>
                <StringField
                    onChange={() => {}}
                    name={"Longitude"}
                    value={value?.coordinate?.long}
                    verify={(x: string) => {
                        const isValid = /^(\+|-)?(?:180(?:(?:\.0{1,6})?)|(?:[0-9]|[1-9][0-9]|1[0-7][0-9])(?:(?:\.[0-9]{1,6})?))$/.test(x)
                        return isValid ? undefined : "Invalid Longitude"
                    }}
                />
            </Box>
            <Button type={"submit"}>Submit</Button>
        </form>
    )
}

export default GeoIPOverrideForm;
