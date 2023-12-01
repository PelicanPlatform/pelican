export async function isLoggedIn() {
    let response = await fetch("/api/v1.0/auth/whoami")
    if(!response.ok){
        return false
    }
    let json = await response.json()
    return json['authenticated']
}
