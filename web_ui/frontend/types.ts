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

export interface Namespace {
  path: string;
  capabilities: Capabilities;
  tokenGeneration: TokenGeneration[];
  tokenIssuer: TokenIssuer[];
  fromTopology: boolean;
}

interface ServerBase {
  name: string;
  storageType: string;
  disableDirectorTest: boolean;
  authUrl: string;
  brokerUrl: string;
  url: string;
  webUrl: string;
  type: string;
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
  namespaces: Namespace[];
}

export interface ServerGeneral extends ServerBase {
  namespacePrefixes: string[];
}
