import {Namespace} from "@/components/Main";
import {Authenticated} from "@/helpers/login";
import React from "react";

import {Card} from "./Card";

export const OriginCard = ({
                              namespace,
                              authenticated
                          } : {namespace: Namespace, authenticated?: Authenticated}) => {
    return (
        <Card namespace={namespace} authenticated={authenticated} editUrl={`/registry/origin/edit/?id=${namespace.id}`}/>
    )
}

export default OriginCard;