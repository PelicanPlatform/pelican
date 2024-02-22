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
