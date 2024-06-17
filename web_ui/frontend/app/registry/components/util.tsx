import React from "react";
import {secureFetch} from "@/helpers/login";
import {Alert, Namespace} from "@/index";
import {getErrorMessage} from "@/helpers/util";

export const populateKey = (o: any, key: string[], value: any) => {
    let i = 0;
    for (; i < key.length - 1; i++) {
        if (!o[key[i]]) {
            o[key[i]] = {};
        }
        o = o[key[i]];
    }
    o[key[i]] = value;
}

export const calculateKeys = (key: string) => {
    if(key.startsWith("admin_metadata.")){
        return ["admin_metadata", key.substring(15)]
    }

    if(key.startsWith("custom_fields.")){
        return ["custom_fields", key.substring(14)]
    }

    return [key]
}

export const getValue = (o: any, key: string[]) : string | undefined => {

    if (o === undefined) {
        return undefined
    }

    if(key.length === 1){
        return o[key[0]]
    }
    return getValue(o[key[0]], key.slice(1))
}

export const deleteKey = (o: any, key: string[]) => {
    let i = 0;
    for (; i < key.length; i++) {
        if (!o[key[i]]) {
            return;
        }
        o = o[key[i]];
    }
    delete o[key[i]];
    return o
}

const handleRequestAlert = async (url: string, options: any) : Promise<Alert | undefined> => {
    try {
        const response = await secureFetch(url, options)

        if(!response.ok){
            let errorMessage = await getErrorMessage(response)
            return {severity: "error", message: errorMessage}
        }

    } catch (e) {
        return {severity: "error", message: `Fetch error: ${e}`}
    }
}

const namespaceFormNodeToJSON = (formData: FormData) => {
    let data: any = {}
    formData.forEach((value: any, name: any) => {
        populateKey(data, calculateKeys(name), value)
    })
    return data
}

export const namespaceToCache = (data: Namespace) => {
    // Build the cache prefix
    if (data.prefix.startsWith("/caches/")) {
        return data
    }

    data['prefix'] = `/caches/${data.prefix}`
    return data
}

export const namespaceToOrigin = (data: Namespace) => {
    // Build the cache prefix
    if (data.prefix.startsWith("/origins/")) {
        return data
    }

    data['prefix'] = `/origins/${data.prefix}`
    return data
}

export const getNamespace = async (id: string | number) : Promise<Namespace | undefined> => {
    const url = new URL(`/api/v1.0/registry_ui/namespaces/${id}`, window.location.origin)
    const response = await fetch(url)
    if (response.ok) {
        return await response.json()
    } else {
        throw new Error(await getErrorMessage(response))
    }
}

export const postGeneralNamespace = async (data: Namespace) : Promise<Alert | undefined> => {
    return await handleRequestAlert("/api/v1.0/registry_ui/namespaces", {
        body: JSON.stringify(data),
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        credentials: "include"
    })
}

export const putGeneralNamespace = async (data: Namespace): Promise<Alert | undefined> => {
    return await handleRequestAlert(`/api/v1.0/registry_ui/namespaces/${data.id}`, {
        body: JSON.stringify(data),
        method: "PUT",
        headers: {
            "Content-Type": "application/json"
        },
        credentials: "include"
    })
}

export const submitNamespaceForm = async (
    data: Partial<Namespace>,
    toUrl: URL | undefined,
    handleSubmit: (data: Partial<Namespace>) => Promise<Alert | undefined>
) => {

    const submitAlert = await handleSubmit(data)

    // Clear the form on successful submit
    if (submitAlert == undefined) {
        window.location.href = toUrl ? toUrl.toString() : "/view/registry/"
    }

    return submitAlert
}
