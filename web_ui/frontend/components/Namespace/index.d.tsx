import {PendingCardProps} from "./PendingCard";
import {CardProps} from "./Card";

export interface NamespaceAdminMetadata {
    user_id: string;
    description: string;
    site_name: string;
    institution: string;
    security_contact_user_id: string;
    status: "Pending" | "Approved" | "Denied" | "Unknown";
    approver_id: number;
    approved_at: string;
    created_at: string;
    updated_at: string;
}

export interface FlatObject {
    [key: string]: Exclude<any, object>;
}

export type NamespaceCardProps = CardProps & PendingCardProps
