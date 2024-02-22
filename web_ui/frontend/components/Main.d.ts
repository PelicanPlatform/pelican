import {NamespaceAdminMetadata} from "@/components/Namespace";

interface Alert {
    severity: "error" | "warning" | "info" | "success";
    message: string;
}

export interface Namespace {
    id: number;
    prefix: string;
    pubkey: string;
    type: "origin" | "cache";
    admin_metadata: NamespaceAdminMetadata;
}

interface Institution {
    id: string;
    name: string;
}