const stringToTime = (time: string) => {
    return new Date(Date.parse(time)).toLocaleString()
}

export const getEnabledServers = async () => {
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
