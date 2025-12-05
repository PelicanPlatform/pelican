export interface ServiceRegistration {
  id: number;
  prefix: string;
  identity: string;
  pubkey: string;
  admin_metadata: {
    userId: string;
    description: string;
    site_name: string;
    institution: string;
    security_contact_user_id: string;
    status: string;
    approver_id: string;
    approved_at: string;
    created_at: string;
    updatedAt: string;
  };
  custom_fields: Record<string, unknown>;
}

export interface ServerRegistration {
  id: string;
  name: string;
  is_origin: boolean;
  is_cache: boolean;
  note: string;
  registration: ServiceRegistration[];
}
