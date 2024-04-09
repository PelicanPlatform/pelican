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