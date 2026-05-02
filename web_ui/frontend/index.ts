import { NamespaceAdminMetadata } from '@/components/Namespace';
import { Capabilities } from '@/types';

export interface User {
  authenticated: boolean;
  role?: 'admin' | 'user' | 'guest';
  user?: string;
  // displayName is the human label from the User row, surfaced by
  // /whoami so the navbar / other always-mounted UI can render it
  // without a separate /me round-trip. Empty when the row has no
  // display name set; callers should fall back to `user`.
  displayName?: string;
  csrfToken?: string;
  // scopes is the caller's effective user-grantable scope set as
  // returned by /whoami: DB user_scopes ∪ DB group_scopes via
  // membership ∪ config-derived grants ∪ admin implications.
  // Used to gate UI surfaces below the granularity of `role`:
  // server.user_admin lets a non-system-admin into /settings/users,
  // server.collection_admin into the collection-management surfaces,
  // etc. Empty/undefined for unauthenticated callers.
  scopes?: string[];
  // requiresAup is true when the server has an AUP configured AND the
  // caller has not yet accepted the active version. AuthenticatedContent
  // routes the caller to /aup/ when this is true, so the signing flow
  // happens on a dedicated page rather than as a stream of 403 errors.
  requiresAup?: boolean;
  // aupVersion is the version hash of the AUP the caller is being asked
  // to accept. The /aup acceptance page passes it back to the
  // /me/aup endpoint to record the agreement against the right text.
  aupVersion?: string;
}

// hasScope reports whether the supplied User holds `scope` in their
// effective set. Backend-side EffectiveScopesForIdentity already
// applies the server.admin → server.user_admin/collection_admin
// implication, so a system admin returns true for every management
// scope without the frontend needing its own implication table.
export const hasScope = (user: User | undefined, scope: string): boolean =>
  !!user?.scopes?.includes(scope);

export type ServerType = 'registry' | 'director' | 'origin' | 'cache';

export interface Server {
  name: string;
  authUrl: string;
  brokerUrl: string;
  url: string;
  webUrl: string;
  type: 'Origin' | 'Cache';
  latitude: number;
  longitude: number;
  capabilities: Capabilities;
  filtered: boolean;
  filteredType: string;
  fromTopology: boolean;
  healthStatus: string;
  namespacePrefixes: string[];
}

export type StringTree = { [key: string]: StringTree | true };

export interface Alert {
  severity: 'error' | 'warning' | 'info' | 'success';
  message: string;
}

export interface RegistryNamespace {
  id: number;
  prefix: string;
  adjustedPrefix?: string; // This value is the same when type is 'namespace' otherwise it removes the type value
  pubkey: string;
  type: 'origin' | 'cache' | 'namespace';
  admin_metadata: NamespaceAdminMetadata;
  custom_fields?: Record<string, any>;
}

export interface Institution {
  id: string;
  name: string;
}
