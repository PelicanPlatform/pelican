import React from "react";

import {StringField} from "./StringField";
import type {CustomRegistrationFieldProps} from "./index.d";

const JWKPlaceholder = {
    "keys": [
        {
            "alg": "ES256",
            "crv": "P-256",
            "kid": "<Your-kid>",
            "kty": "EC",
            "x": "",
            "y": ""
        }
    ]
}

const pubkeyValidator = (value: string) => {
    try {
        JSON.parse(value)
        return undefined
    } catch (e) {
        return "Invalid pubkey format"
    }
}

const PubkeyField = ({...props}: CustomRegistrationFieldProps<string>) => {
    return <StringField
        multiline={true}
        inputProps={{
            style: {
                fontFamily: "monospace",
                fontSize: "0.8rem",
                lineHeight: "0.9rem",
                minHeight: "1.5rem",
                paddingTop: "0.6rem",
            }
        }}
        placeholder={JSON.stringify(JWKPlaceholder, null, 2)}
        validator={pubkeyValidator}
        {...props}
    />
}

export default PubkeyField;
export {PubkeyField}