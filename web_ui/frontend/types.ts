export interface Capabilities {
  PublicReads: boolean;
  Reads: boolean;
  Writes: boolean;
  Listings: boolean;
  DirectReads: boolean;
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

export interface User {
  id: string;
  username: string;
  sub: string;
  issuer: string;
  createdAt: string;
}

export type UserPost = Omit<User, 'id' | 'createdAt'>;

export type UserPatch = Partial<Omit<User, 'createdAt'>>;

export interface Group {
  id: string;
  name: string;
  description: string;
  members: User[];
  createdBy: string;
  createdAt: string;
}

export type GroupPost = Omit<Group, 'members' | 'createdBy' | 'createdAt'>;

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

export interface WellKnownConfiguration {
  director_endpoint: string;
  namespace_registration_endpoint: string;
  jwks_uri: string;
}
