import {NamespaceAdminMetadata} from "@/components/Namespace";

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

export interface Server {
    "name": string;
    "authUrl": string;
    "brokerUrl": string;
    "url": string;
    "webUrl": string;
    "type": "Origin" | "Cache";
    "latitude": number;
    "longitude": number;
    "enableWrite": boolean;
    "enableFallbackRead": boolean;
    "filtered": boolean;
    "filteredType": string;
    "status": string;
}
