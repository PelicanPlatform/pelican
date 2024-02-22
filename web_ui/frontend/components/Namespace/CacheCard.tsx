import {Namespace} from "@/components/Main";
import {Authenticated} from "@/helpers/login";
import React from "react";

import {Card} from "./Card";

export const CacheCard = ({
                              namespace,
                              authenticated
                          } : {namespace: Namespace, authenticated?: Authenticated}) => {

    namespace.prefix = namespace.prefix.replace("/cache/", "")

    return (
        <Card namespace={namespace} authenticated={authenticated} editUrl={`/registry/cache/edit/?id=${namespace.id}`}/>
    )
}

export default CacheCard;
