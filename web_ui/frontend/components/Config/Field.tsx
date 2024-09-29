import {
  AuthorizationTemplate,
  CustomRegistrationField,
  Duration,
  Export,
  GeoIPOverride,
  Institution,
  IPMapping,
  Lot,
  OIDCAuthenticationRequirement,
  Parameter,
  ParameterInputProps,
} from '@/components/Config/index';
import {
  BooleanField,
  DurationField,
  IntegerField,
  StringField,
  StringSliceField,
} from '../Config';
import React from 'react';
import {
  CustomRegistrationFieldForm,
  ExportForm,
  ObjectField,
  GeoIPOverrideForm,
  InstitutionForm,
  OIDCAuthenticationRequirementForm,
  LotForm,
} from './ObjectField';
import { buildPatch } from '@/components/Config/util';
import IPMappingForm from '@/components/Config/ObjectField/IPMappingForm';
import AuthorizationTemplateForm from '@/components/Config/ObjectField/AuthorizationTemplateForm';

const Field = ({ onChange, ...props }: ParameterInputProps) => {
  function handleChange<T>(value: T) {
    onChange(buildPatch(props.name, value));
  }

  switch (props.type) {
    case 'bool':
      return (
        <BooleanField
          onChange={handleChange<boolean>}
          name={props.name}
          value={props.Value as boolean}
        />
      );
    case 'duration':
      return (
        <DurationField
          onChange={handleChange<Duration>}
          name={props.name}
          value={props.Value as number}
        />
      );
    case 'stringSlice':
      return (
        <StringSliceField
          onChange={handleChange<string[]>}
          name={props.name}
          value={props.Value as string[]}
        />
      );
    case 'string':
      return (
        <StringField
          onChange={handleChange<string>}
          name={props.name}
          value={props.Value as string}
        />
      );
    case 'filename':
      return (
        <StringField
          onChange={handleChange<string>}
          name={props.name}
          value={props.Value as string}
        />
      );
    case 'url':
      return (
        <StringField
          onChange={handleChange<string>}
          name={props.name}
          value={props.Value as string}
        />
      );
    case 'int':
      return (
        <IntegerField
          onChange={handleChange<number>}
          name={props.name}
          value={props.Value as number}
        />
      );
    case 'object':
      switch (props.name.split('.').slice(-1)[0]) {
        case 'Institutions':
          return (
            <ObjectField<Institution>
              onChange={handleChange<Institution[]>}
              name={props.name}
              value={props.Value as Institution[]}
              Form={InstitutionForm}
              keyGetter={(v) => v.name}
            />
          );
        case 'GeoIPOverrides':
          return (
            <ObjectField
              onChange={handleChange<GeoIPOverride[]>}
              name={props.name}
              value={props.Value as GeoIPOverride[]}
              Form={GeoIPOverrideForm}
              keyGetter={(v) => v.ip}
            />
          );
        case 'OIDCAuthenticationRequirements':
          return (
            <ObjectField
              onChange={handleChange<OIDCAuthenticationRequirement[]>}
              name={props.name}
              value={props.Value as OIDCAuthenticationRequirement[]}
              Form={OIDCAuthenticationRequirementForm}
              keyGetter={(v) => v.value + v.claim}
            />
          );
        case 'AuthorizationTemplates':
          return (
            <ObjectField
              onChange={handleChange<AuthorizationTemplate[]>}
              name={props.name}
              value={props.Value as AuthorizationTemplate[]}
              Form={AuthorizationTemplateForm}
              keyGetter={(v) => v.prefix}
            />
          );
        case 'IPMapping':
          return (
            <ObjectField
              onChange={handleChange<IPMapping[]>}
              name={props.name}
              value={props.Value as IPMapping[]}
              Form={IPMappingForm}
              keyGetter={(v) => ('all' in v ? v.all : v.source)}
            />
          );
        case 'CustomRegistrationFields':
          return (
            <ObjectField
              onChange={handleChange<CustomRegistrationField[]>}
              name={props.name}
              value={props.Value as CustomRegistrationField[]}
              Form={CustomRegistrationFieldForm}
              keyGetter={(v) => v.name}
            />
          );
        case 'Exports':
          return (
            <ObjectField
              onChange={handleChange<Export[]>}
              name={props.name}
              value={props.Value as Export[]}
              Form={ExportForm}
              keyGetter={(v) => v.federationprefix}
            />
          );
        case 'Lots':
          return (
            <ObjectField
              onChange={handleChange<Lot[]>}
              name={props.name}
              value={props.Value as Lot[]}
              Form={LotForm}
              keyGetter={(v) => v.lotname}
            />
          );
        default:
          console.log('Unknown type: ' + props.type);
      }
      break;

    default:
      console.log('Unknown type: ' + props.type);
  }
};

export default Field;
