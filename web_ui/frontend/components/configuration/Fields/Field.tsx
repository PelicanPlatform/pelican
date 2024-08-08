import React, { useMemo } from 'react';

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
  ParameterInputProps,
  BooleanField,
  DurationField,
  IntegerField,
  StringField,
  StringSliceField,
  CustomRegistrationFieldForm,
  ExportForm,
  ObjectField,
  GeoIPOverrideForm,
  InstitutionForm,
  OIDCAuthenticationRequirementForm,
  LotForm,
  IPMappingForm,
  AuthorizationTemplateForm,
} from '@/components/configuration';
import { buildPatch } from '@/components/configuration/util';
import { LoadingField } from '@/components/configuration/Fields/LoadingField';

const Field = ({
  onChange,
  value,
  name,
  focused,
  ...props
}: ParameterInputProps) => {
  const handleChange = useMemo(() => {
    return <T,>(value: T) => {
      return onChange({ [name]: value });
    };
  }, [value, name, onChange]);

  // If the value is undefined then return loading field
  if (value === undefined) {
    return <LoadingField name={name} />;
  }

  // Otherwise use the field that corresponds to the identified type
  switch (props.type) {
    case 'bool':
      return (
        <BooleanField
          focused={focused}
          onChange={handleChange<boolean>}
          name={name}
          value={value as boolean}
        />
      );
    case 'duration':
      return (
        <DurationField
          focused={focused}
          onChange={handleChange<Duration>}
          name={name}
          value={value as number}
        />
      );
    case 'stringSlice':
      return (
        <StringSliceField
          focused={focused}
          onChange={handleChange<string[]>}
          name={name}
          value={value as string[]}
        />
      );
    case 'string':
      return (
        <StringField
          focused={focused}
          onChange={handleChange<string>}
          name={name}
          value={value as string}
        />
      );
    case 'filename':
      return (
        <StringField
          focused={focused}
          onChange={handleChange<string>}
          name={name}
          value={value as string}
        />
      );
    case 'url':
      return (
        <StringField
          focused={focused}
          onChange={handleChange<string>}
          name={name}
          value={value as string}
        />
      );
    case 'int':
      return (
        <IntegerField
          focused={focused}
          onChange={handleChange<number>}
          name={name}
          value={value as number}
        />
      );
    case 'object':
      switch (name.split('.').slice(-1)[0]) {
        case 'Institutions':
          return (
            <ObjectField<Institution>
              onChange={handleChange<Institution[]>}
              name={name}
              value={value as Institution[]}
              Form={InstitutionForm}
              keyGetter={(v) => v.name}
            />
          );
        case 'GeoIPOverrides':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<GeoIPOverride[]>}
              name={name}
              value={value as GeoIPOverride[]}
              Form={GeoIPOverrideForm}
              keyGetter={(v) => v.ip}
            />
          );
        case 'OIDCAuthenticationRequirements':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<OIDCAuthenticationRequirement[]>}
              name={name}
              value={value as OIDCAuthenticationRequirement[]}
              Form={OIDCAuthenticationRequirementForm}
              keyGetter={(v) => v.value + v.claim}
            />
          );
        case 'AuthorizationTemplates':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<AuthorizationTemplate[]>}
              name={name}
              value={value as AuthorizationTemplate[]}
              Form={AuthorizationTemplateForm}
              keyGetter={(v) => v.prefix}
            />
          );
        case 'IPMapping':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<IPMapping[]>}
              name={name}
              value={value as IPMapping[]}
              Form={IPMappingForm}
              keyGetter={(v) => ('all' in v ? v.all : v.source)}
            />
          );
        case 'CustomRegistrationFields':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<CustomRegistrationField[]>}
              name={name}
              value={value as CustomRegistrationField[]}
              Form={CustomRegistrationFieldForm}
              keyGetter={(v) => v.name}
            />
          );
        case 'Exports':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<Export[]>}
              name={name}
              value={value as Export[]}
              Form={ExportForm}
              keyGetter={(v) => v.federationprefix}
            />
          );
        case 'Lots':
          return (
            <ObjectField
              focused={focused}
              onChange={handleChange<Lot[]>}
              name={name}
              value={value as Lot[]}
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
