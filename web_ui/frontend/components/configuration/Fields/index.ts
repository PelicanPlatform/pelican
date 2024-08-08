import BooleanField from './BooleanField';
import StringField from './StringField';
import DurationField from './DurationField';
import StringSliceField from './StringSliceField';
import IntegerField from './IntegerField';
import MultiSelectField from './MultiSelectField';
import SelectField from './SelectField';
import DateTimeField from './DateTimeField';
import Field from './Field';

export * from './ObjectField';
export {
  BooleanField,
  StringField,
  DurationField,
  StringSliceField,
  IntegerField,
  MultiSelectField,
  SelectField,
  DateTimeField,
  Field,
};

export interface ParameterMetadata {
  name: string;
  description: string;
  type:
    | 'bool'
    | 'filename'
    | 'duration'
    | 'int'
    | 'object'
    | 'string'
    | 'url'
    | 'stringSlice';
  default: string;
  components: string[];
}

export type ParameterValue =
  | string
  | number
  | boolean
  | string[]
  | undefined
  | Coordinate[]
  | Institution[]
  | CustomRegistrationField[]
  | OIDCAuthenticationRequirement[]
  | AuthorizationTemplate[]
  | IPMapping[]
  | GeoIPOverride[]
  | Export[]
  | Lot[];

export type ParameterValueRecord = { [key: string]: ParameterValue };

// This is how we receive the metadata from the backend API
export type ParameterMetadataList = { [key: string]: ParameterMetadata }[];

// This is how we want to store it for future interactions
export type ParameterMetadataRecord = { [key: string]: ParameterMetadata };

export type ParameterInputProps = ParameterMetadata & {
  focused?: boolean;
  value?: ParameterValue;
  onChange: (patch: any) => void;
};

export type DurationString =
  `${number}${'ns' | 'us' | 'µs' | 'ms' | 's' | 'm' | 'h'}`;

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

export type FieldType = 'string' | 'int' | 'bool' | 'datetime' | 'enum';

export interface CustomRegistrationField {
  name: string;
  type: FieldType;
  description: string;
  required: boolean;
  validationurl?: string;
  options?: Option[];
  optionsurl?: string;
}

export interface OIDCAuthenticationRequirement {
  claim: string;
  value: string;
}

export type Action = 'read' | 'modify' | 'create';

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

export type Capability =
  | 'PublicReads'
  | 'DirectReads'
  | 'Writes'
  | 'Listings'
  | 'Reads';

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

export type Config = {
  [key: string]: ParameterValue | Config;
};
