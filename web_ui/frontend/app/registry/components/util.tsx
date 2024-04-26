import React from "react";
import {secureFetch} from "@/helpers/login";
import {Alert, Namespace} from "@/components/Main";

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

export const getValue = (o: any, key: string[]) => {
    let i = 0;
    for (; i < key.length - 1; i++) {
        if (!o[key[i]]) {
            return undefined;
        }
        o = o[key[i]];
    }
    return o[key[i]];
}

export const deleteKey = (o: any, key: string[]) => {
    let i = 0;
    for (; i < key.length - 1; i++) {
        if (!o[key[i]]) {
            return;
        }
        o = o[key[i]];
    }
    delete o[key[i]];
}

const handleRequestAlert = async (url: string, options: any) : Promise<Alert | undefined> => {
    try {
        const response = await secureFetch(url, options)

        if(!response.ok){
            try {
                let data = await response.json()
                return {severity: "error", message: response.status + ": " + data['error']}
            } catch (e) {
                return {severity: "error", message: `Failed to make request`}
            }
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
    data['prefix'] = `/caches/${data.prefix}`

    return data
}

export const getNamespace = async (id: string | number) : Promise<Namespace | undefined> => {
    const url = new URL(`/api/v1.0/registry_ui/namespaces/${id}`, window.location.origin)
    const response = await fetch(url)
    if (response.ok) {
        return await response.json()
    } else {
        try {
            let data = await response.json()
            throw new Error(data?.error)
        } catch (e) {
            throw new Error(`Failed to fetch namespace: ${id}`)
        }
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
    handleSubmit: (data: Partial<Namespace>) => Promise<Alert | undefined>
) => {

    const submitAlert = await handleSubmit(data)

    // Clear the form on successful submit
    if (submitAlert == undefined) {
        window.location.href = "/view/registry/"
    }

    return submitAlert
}
