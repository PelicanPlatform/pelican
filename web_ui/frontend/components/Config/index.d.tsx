export type Parameter = ParameterMetadata & ParameterValue;

export interface ParameterMetadata {
    name: string;
    description: string;
    type: "bool" | "filename" | "duration" | "int" | "object" | "string" | "url" | "stringSlice";
    default: string;
    components: string[];
}

export interface ParameterValue {
    Type: string;
    Value: string | number | boolean | string[] | undefined | Coordinate[] | Institution[] | CustomRegistrationField[] | OIDCAuthenticationRequirement[] | AuthorizationTemplate[] | IPMapping[] | GeoIPOverride[] | Export[] | Lot[];
}

export type ParameterInputProps = Parameter & {
    onChange: (patch: any) => void;
}

export type DurationString = `${number}${"ns" | "us" | "µs" | "ms" |"s" | "m" | "h"}`;

export type Duration = number | DurationString;

export interface Coordinate {
    lat: string;
    long: string;
}

export interface GeoIPOverride {
    ip: string;
    coordinate: Coordinate;
}

export interface Institution {
    id: string;
    name: string;
}

export interface Option {
    id: string;
    name: string;
}

export type FieldType = "string" | "int" | "bool" | "datetime" | "enum";

export interface CustomRegistrationField {
    name: string;
    type: FieldType;
    description: string;
    required: boolean;
    validationurl?: string;
    options?: Option[];
    optionurl?: string;
}

export interface OIDCAuthenticationRequirement {
    claim: string;
    value: string;
}

export type Action = "read" | "modify" | "create";

export interface AuthorizationTemplate {
    actions: Action[];
    prefix: string;
}

export interface IPMappingAll {
    all: string;
}

export interface IPMappingFine {
    source: string;
    dest: string;
}

export type IPMapping = IPMappingAll | IPMappingFine;


export type Capability = "PublicReads" | "DirectReads" | "Writes" | "Listings" | "Reads";

export interface Export {
    storageprefix: string;
    federationprefix: string;
    capabilities: Capability[];
    sentinellocation: string;
}

export interface Path {
    path: string;
    recursive: boolean;
}

export interface ManagementPolicyAttrs {
    dedicatedgb: number;
    opportunisticgb: number;
    maxnumberobjects: {
        value: number;
    };
    creationtime: {
        value: number;
    };
    expirationtime: {
        value: number;
    };
    deletiontime: {
        value: number;
    };
}

export interface Lot {
    lotname: string;
    owner: string;
    paths: Path[];
    managementpolicyattrs: ManagementPolicyAttrs;
}

export interface ConfigMetadata {
    [key: string]: ConfigMetadataValue
}

export interface ConfigMetadataValue {
    components: string[]
    default: boolean
    description: string
    name: string
    type: string
}

export type Config = {
    [key: string]: ParameterInputProps | Config
}
