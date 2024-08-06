import { Config, ParameterInputProps } from '@/components/Config/index';
import { Box, Button, Typography } from '@mui/material';
import { Field } from '@/components/Config';
import { QuestionMark } from '@mui/icons-material';
import { OverridableStringUnion } from '@mui/types';
import { Variant } from '@mui/material/styles/createTypography';
import { TypographyPropsVariantOverrides } from '@mui/material/Typography';
import React from 'react';
import { isConfig, sortConfig } from '@/app/config/util';

export interface ConfigDisplayProps {
  id: string[];
  name: string;
  value: Config | ParameterInputProps;
  level: number;
  onChange: (patch: any) => void;
}

export function ConfigDisplay({
  id,
  name,
  value,
  level = 1,
  onChange,
}: ConfigDisplayProps) {
  if (name != '') {
    id = [...id, name];
  }

  // If this is a ConfigValue then display it
  if (!isConfig(value)) {
    return (
      <Box pt={2} display={'flex'} id={id.join('-')}>
        <Box flexGrow={1} minWidth={0}>
          <Field {...(value as ParameterInputProps)} onChange={onChange} />
        </Box>

        <Button
          size={'small'}
          href={`https://docs.pelicanplatform.org/parameters#${id.join('-')}`}
          target={'_blank'}
        >
          <QuestionMark />
        </Button>
      </Box>
    );
  }

  // If this is a Config then display all of its values
  let subValues = Object.entries(value);
  subValues.sort(sortConfig);

  let configDisplays = subValues.map(([k, v]) => {
    return (
      <ConfigDisplay
        id={id}
        key={k}
        name={k}
        value={v}
        level={level + 1}
        onChange={onChange}
      />
    );
  });

  let variant: OverridableStringUnion<
    'inherit' | Variant,
    TypographyPropsVariantOverrides
  >;
  switch (level) {
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
    <>
      {name ? (
        <Typography
          id={id.join('-')}
          variant={variant}
          component={variant}
          mt={2}
        >
          {name}
        </Typography>
      ) : undefined}
      {configDisplays}
    </>
  );
}

export default ConfigDisplay;
