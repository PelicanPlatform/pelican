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

export interface DowntimeGet extends DowntimeBase {
  id: string;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
}

export type DowntimePut = Partial<DowntimeBase>;
