'use client';

import React, { memo } from 'react';
import { Box, Button, Typography } from '@mui/material';
import { QuestionMark } from '@mui/icons-material';
import { OverridableStringUnion } from '@mui/types';
import { Variant } from '@mui/material/styles/createTypography';
import { TypographyPropsVariantOverrides } from '@mui/material/Typography';

import {
  Field as NonMemoizedField,
  ParameterMetadata,
  ParameterMetadataRecord,
  ParameterValue,
  ParameterValueRecord,
} from '@/components/configuration';
import { isEqual } from 'lodash';

// Memoize Expensive Components
const Field = memo(NonMemoizedField);

export interface ConfigDisplayProps {
  config?: ParameterValueRecord;
  patch: ParameterValueRecord;
  metadata: ParameterMetadataRecord;
  onChange: (patch: any) => void;
}

export const ConfigDisplay = memo(NonMemoizedConfigDisplay);

export function NonMemoizedConfigDisplay({
  config,
  metadata,
  patch,
  onChange,
}: ConfigDisplayProps) {
  const existingLabels = new Set<string>();

  return (
    <>
      {Object.entries(metadata).map(([name, parameterMetadata]) => {
        let label = null;
        let groupName = name.split('.').slice(0, -1).join('.');

        if (!existingLabels.has(groupName)) {
          existingLabels.add(groupName);
          label = <ConfigCategoryLabel name={groupName} />;
        }

        return (
          <Box key={name}>
            {label}
            <ConfigField
              metadata={parameterMetadata}
              value={name in patch ? patch[name] : config?.[name]}
              focused={name in patch && !isEqual(patch[name], config?.[name])}
              onChange={onChange}
            />
          </Box>
        );
      })}
    </>
  );
}

interface ConfigFieldProps {
  metadata: ParameterMetadata;
  value: ParameterValue;
  onChange: (patch: any) => void;
  focused: boolean;
}

export const ConfigField = ({
  metadata,
  value,
  onChange,
  focused,
}: ConfigFieldProps) => {
  return (
    <Box pt={2} display={'flex'} id={metadata.name.split('.').join('-')}>
      <Box flexGrow={1} minWidth={0}>
        <Field
          {...(metadata as ParameterMetadata)}
          value={value}
          onChange={onChange}
          focused={focused}
        />
      </Box>
      <Button
        size={'small'}
        href={`https://docs.pelicanplatform.org/parameters#${metadata.name.split('.').join('-')}`}
        target={'_blank'}
      >
        <QuestionMark />
      </Button>
    </Box>
  );
};

export const ConfigCategoryLabel = ({ name }: { name: string }) => {
  const splitName = name.split('.');

  let variant: OverridableStringUnion<
    'inherit' | Variant,
    TypographyPropsVariantOverrides
  >;
  switch (splitName.length) {
    case 1:
      variant = 'h1';
      break;
    case 2:
      variant = 'h2';
      break;
    case 3:
      variant = 'h3';
      break;
    case 4:
      variant = 'h4';
      break;
    case 5:
      variant = 'h5';
      break;
    case 6:
      variant = 'h6';
      break;
    default:
      variant = 'h6';
  }

  return (
    <Typography id={splitName.join('-')} component={variant} mt={2}>
      {splitName.pop()}
    </Typography>
  );
};

export default ConfigDisplay;
