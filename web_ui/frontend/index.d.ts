import {NamespaceAdminMetadata} from "@/components/Namespace";

export interface User {
    authenticated: boolean;
    role?: "admin" | "user" | "guest";
    user?: string;
    csrfToken?: string;
}

export type ServerType = "registry" | "director" | "origin" | "cache"

export interface Server {
    "name": string;
    "authUrl": string;
    "brokerUrl": string;
    "url": string;
    "webUrl": string;
    "type": "Origin" | "Cache";
    "latitude": number;
    "longitude": number;
    "capabilities": Capabilities;
    "filtered": boolean;
    "filteredType": string;
    "fromTopology": boolean;
    "healthStatus": string;
    "namespacePrefixes": string[];
}

export interface Capabilities {
    PublicReads: boolean;
    Reads: boolean;
    Writes: boolean;
    Listings: boolean;
    DirectReads: boolean;
}

export type StringTree = Record<string, StringTree | true>

interface Alert {
    severity: "error" | "warning" | "info" | "success";
    message: string;
}

export interface Namespace {
    id: number;
    prefix: string;
    pubkey: string;
    type: "origin" | "cache" | "namespace";
    admin_metadata: NamespaceAdminMetadata;
    custom_fields?: Record<string, any>;
}

interface Institution {
    id: string;
    name: string;
}
