export interface Capabilities {
  PublicRead: boolean;
  Read: boolean;
  Write: boolean;
  Listing: boolean;
  FallBackRead: boolean;
}

export interface TokenGeneration {
  strategy: string;
  vaultServer: string;
  maxScopeDepth: number;
  issuer: string;
}

export interface TokenIssuer {
  basePaths: string[];
  restrictedPaths: string[] | null;
  issuer: string;
}

export interface DirectorNamespace {
  path: string;
  capabilities: Capabilities;
  tokenGeneration: TokenGeneration[] | null;
  tokenIssuer: TokenIssuer[] | null;
  fromTopology: boolean;
  caches: string[];
  origins: string[];
}

export type ServerType = 'Origin' | 'Cache';

interface ServerBase {
  name: string;
  version: string;
  storageType: string;
  disableDirectorTest: boolean;
  authUrl: string;
  brokerUrl: string;
  url: string;
  webUrl: string;
  type: ServerType;
  latitude: number;
  longitude: number;
  capabilities: Capabilities;
  filtered: boolean;
  filteredType: string;
  fromTopology: boolean;
  healthStatus: string;
  serverStatus:
    | 'shutting down'
    | 'critical'
    | 'degraded'
    | 'warning'
    | 'ok'
    | 'unknown';
  ioLoad: number;
}

export interface ServerDetailed extends ServerBase {
  namespaces: DirectorNamespace[];
}

export interface ServerGeneral extends ServerBase {
  namespacePrefixes: string[];
}

/**
 * Types for downtime interactions
 */

export type DowntimeClass = 'SCHEDULED' | 'UNSCHEDULED';
export type DowntimeSeverity =
  | 'Outage (completely inaccessible)'
  | 'Severe (most services down)'
  | 'Intermittent Outage (may be up for some of the time)'
  | "No Significant Outage Expected (you shouldn't notice)";

export interface DowntimeBase {
  class: DowntimeClass;
  description: string;
  severity: DowntimeSeverity;
  startTime: number;
  endTime: number;
}

export interface DowntimePost extends DowntimeBase {}

export interface DowntimeRegistryPost extends DowntimeBase {
  serverName: string;
  serverId: string;
}

export interface DowntimeGet extends DowntimeBase {
  id: string;
  serverName: string;
  serverId: string;
  source: string;
  createdBy: string;
  createdAt: number;
  updatedBy: string;
  updatedAt: number;
}

export type DowntimePut = Partial<DowntimeBase>;

/**
 * Token Types
 */

export interface BaseToken {
  name: string;
  expiration: string;
  scopes: string[];
}

export interface GetToken extends BaseToken {
  id: string;
  createdBy: string;
}

/** Groups and Authorization Types */

export type UserStatus = 'active' | 'inactive';

export interface User {
  id: string;
  username: string;
  sub: string;
  issuer: string;
  status: UserStatus;
  lastLoginAt: string | null;
  displayName: string;
  aupVersion: string;
  aupAgreedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type UserPost = Omit<
  User,
  | 'id'
  | 'createdAt'
  | 'updatedAt'
  | 'status'
  | 'lastLoginAt'
  | 'displayName'
  | 'aupVersion'
  | 'aupAgreedAt'
>;

export type UserPatch = Partial<Omit<User, 'createdAt'>>;

export type AdminType = 'user' | 'group';

// UserCard / GroupCard mirror the backend's database.UserCard / GroupCard:
// the minimum needed to render an identity ("Display Name (username)")
// without pulling the full record or requiring user-listing privilege.
export interface UserCard {
  id: string;
  username: string;
  displayName: string;
}
export interface GroupCard {
  id: string;
  name: string;
}

export interface Group {
  id: string;
  // Machine-readable identifier; admin-only renames. Used in policy
  // strings (admin-group lists, ACL grants) so it must be a stable
  // restricted-character handle.
  name: string;
  // Human-readable label; owner-editable. UIs that surface a group
  // anywhere it might affect authorization decisions (transfer
  // ownership, add to ACL) should render BOTH "displayName (name)" so
  // admins are not acting on an ambiguous label alone.
  displayName: string;
  description: string;
  // The backend serializes Group.Members as a list of GroupMember rows
  // (membership + nested User), NOT a list of bare Users. UIs must
  // dereference `.user` for the actual identity. The previous typing
  // here as `User[]` was wrong and silently produced "(unset)" labels
  // because `member.username` was always undefined on the wrapper.
  members: GroupMember[];
  createdBy: string;
  ownerId: string;
  adminId: string;
  adminType: AdminType;
  createdAt: string;
  updatedAt: string;
  // Resolved server-side; absent if the referenced user/group no longer
  // exists. The UI falls back to the raw id in that case.
  ownerUser?: UserCard;
  adminUser?: UserCard;
  adminGroup?: GroupCard;
  createdByUser?: UserCard;
}

export type GroupPost = Omit<
  Group,
  | 'members'
  | 'createdBy'
  | 'createdAt'
  | 'updatedAt'
  | 'ownerId'
  | 'adminId'
  | 'adminType'
>;

export interface GroupMember {
  groupId: string;
  userId: string;
  user: User;
  createdBy: string;
  createdAt: string;
}

export type GroupMemberPost = Omit<
  GroupMember,
  'user' | 'addedBy' | 'addedAt' | 'groupId'
>;

export interface GroupInviteLink {
  id: string;
  groupId: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  isSingleUse: boolean;
  redeemedBy: string;
  redeemedAt: string | null;
  revoked: boolean;
  /** Public short identifier — first few chars of the plaintext token.
   * Safe to display in admin UIs and logs; not a credential. */
  tokenPrefix: string;
  /** Optional: when the row was redeemed, the resolved user-card for
   * that user. Backed by the InviteLinkView wrapper in groups.go;
   * lets the UI render a UserPill instead of the raw redeemedBy ID. */
  redeemedByUser?: UserCard;
}

export interface GroupInviteLinkCreated extends GroupInviteLink {
  /** The plaintext invite token, shown only once at creation */
  inviteToken: string;
}

export interface GroupInviteLinkPost {
  isSingleUse: boolean;
  expiresIn: string; // Duration string, e.g. "168h"
}

export interface UserIdentity {
  id: string;
  userId: string;
  sub: string;
  issuer: string;
  createdAt: string;
  updatedAt: string;
}

export type UserIdentityPost = Omit<
  UserIdentity,
  'id' | 'userId' | 'createdAt'
>;

export interface WellKnownConfiguration {
  director_endpoint: string;
  namespace_registration_endpoint: string;
  jwks_uri: string;
}

/**
 * Federation Metadata Discrepancy Types
 */

export interface UrlMismatch {
  directorValue: string;
  discoveryValue: string;
}

export interface MetadataDiscrepancy {
  hasDiscrepancy: boolean;
  directorUrlMismatch?: UrlMismatch;
  registryUrlMismatch?: UrlMismatch;
  jwksHasOverlap: boolean;
  jwksOverlapChecked: boolean;
  jwksError?: string;
  lastChecked: string;
  discoveryUrl: string;
  enabled: boolean;
}

export type JsonPrimitive = string | number | boolean | null;

export interface ServerLocalMetadata {
  id: string;
  name: string;
  type: 'origin' | 'cache' | 'origin_cache' | 'unknown';
  createdAt: string;
  updatedAt: string;
}
