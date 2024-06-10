import {ServerType} from "@/index"

const stringToTime = (time: string) => {
    return new Date(Date.parse(time)).toLocaleString()
}

export const getEnabledServers = async () : Promise<ServerType[]> => {
    const response = await fetch("/api/v1.0/servers")
    if (response.ok) {
        const data = await response.json()
        const servers = data?.servers

        if(servers == undefined){
            console.error("No servers found", response)
            return []
        }

        return servers
    }

    return []
}

export const getOauthEnabledServers = async () => {
    const response = await fetch("/api/v1.0/auth/oauth")
    if (response.ok) {
        const data = await response.json()
        const servers = data?.oidc_enabled_servers

        if(servers == undefined){
            console.error("No servers found", response)
            return []
        }

        return servers
    }
}

export function getObjectValue<T>(obj: any, keys: string[]): T | undefined {
    const currentValue = obj?.[keys[0]]
    if(keys.length == 1){
        return currentValue
    }
    return getObjectValue(currentValue, keys.slice(1))
}

export const getErrorMessage = async (response: Response) : Promise<string> =>  {
    let message;
    try {
        let data = await response.json()
        message = response.status + ": " + data['msg']
    } catch (e) {
        message = response.status + ": " + response.statusText
    }
    return message
}

type TypeOrTypeFunction<T> = T | (() => T)

export function evaluateOrReturn<T>(o: TypeOrTypeFunction<T>) : T {
    return typeof o === 'function' ? (o as () => T)() : o
}
