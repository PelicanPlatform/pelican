import {TextField} from "@mui/material";
import React from "react";

import {Namespace} from "@/components/Main";

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

interface PubkeyFieldProps {
    namespace?: Namespace;
}

const PubkeyField = ({namespace}: PubkeyFieldProps) => {

    const [error, setError] = React.useState<boolean>(false)

    return (
        <TextField
            required
            fullWidth
            size={"small"}
            id={"pubkey"}
            name={"pubkey"}
            label={"Pubkey"}
            variant={"outlined"}
            multiline={true}
            defaultValue={namespace?.pubkey || ""}
            inputProps={{
                style: {
                    fontFamily: "monospace",
                    fontSize: "0.8rem",
                    lineHeight: "0.9rem",
                    minHeight: "1.5rem",
                    paddingTop: "0.6rem",
                }
            }}
            error={error}
            helperText={error ? "Invalid JSON" : "Pubkey is your origin's public JWKS"}
            placeholder={JSON.stringify(JWKPlaceholder, null, 2)}
            onChange={(e) => {
                try {
                    JSON.parse(e.target.value)
                    setError(false)
                } catch (e) {
                    setError(true)
                }
            }}
        />
    )
}

export default PubkeyField
