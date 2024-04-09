export interface User {
    authenticated: boolean;
    role?: "admin" | "user" | "guest";
    user?: string;
    csrfToken?: string;
}

export type ServerType = "registry" | "director" | "origin"
