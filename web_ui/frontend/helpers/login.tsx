
export interface Authenticated {
    authenticated: boolean
    csrf_token: string
    role: string
    time: number
    user: string
}

export async function secureFetch(url: string | URL, options: RequestInit = {}) {
    if(await isLoggedIn()) {

        // If they are logged in, this key must exist
        const authenticated = getJsonFromSessionStorage<Authenticated>("authenticated") as Authenticated

        return await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                "X-CSRF-Token": authenticated.csrf_token
            }
        })
    }

    throw new Error("You must be logged in to make this request")
}

export function getJsonFromSessionStorage<O>(key: string) : O | null {
    if(sessionStorage.getItem(key) !== null) {
        return JSON.parse(sessionStorage.getItem(key) as string)
    }
    return null
}

export function getAuthenticated() : Authenticated | null {
    return getJsonFromSessionStorage<Authenticated>("authenticated")
}

// Allow them to see a page if logged in
export async function isLoggedIn() : Promise<boolean> {

    // If the session is valid then read it
    const authenticated = getJsonFromSessionStorage<Authenticated>("authenticated")
    if(authenticated != null){
        if(authenticated.time + 10000 > Date.now()){
            return authenticated.authenticated
        }
    }

    // Check if the user is authenticated
    try {

        let response = await fetch("/api/v1.0/auth/whoami")
        if(!response.ok){
            return false
        }

        const json = await response.json()
        const authenticated = json['authenticated']

        // If authenticated, store status and csrf token
        if(authenticated){
            sessionStorage.setItem(
                "authenticated",
                JSON.stringify({
                    time: Date.now(),
                    authenticated: true,
                    user: json['user'],
                    role: json['role'],
                    csrf_token: response.headers.get('X-CSRF-Token')
                })
            )
            return true
        }

        return false

    } catch (error) {
        return false
    }
}
