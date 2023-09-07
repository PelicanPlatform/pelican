export async function isLoggedIn() {
    let response = await fetch("/api/v1.0/origin-ui/whoami")
    if(!response.ok){
        return false
    }
    let json = await response.json()
    return json['authenticated']
}
