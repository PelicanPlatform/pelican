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
 * Token Types
 */

export interface BaseToken {
  name: string;
  createdBy: string;
  expiration: string;
  scopes: string[];
}

export interface GetToken extends BaseToken {
  id: string;
}
