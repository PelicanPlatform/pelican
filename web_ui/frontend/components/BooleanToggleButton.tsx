import { Button, ButtonGroup, Tooltip } from '@mui/material';
import { Check, DoNotDisturb, HorizontalRule } from '@mui/icons-material';

interface BooleanToggleButtonProps {
  label: string;
  value?: boolean;
  onChange: (value?: boolean) => void;
}

export const BooleanToggleButton = ({
  label,
  value,
  onChange,
}: BooleanToggleButtonProps) => {
  return (
    <ButtonGroup aria-label={label}>
      <Tooltip title={'Reset'}>
        <Button
            size={'small'}
            variant={value == undefined ? 'contained' : 'outlined'}
            onClick={() => onChange(undefined)}
        >
          {label}
        </Button>
      </Tooltip>
      <Tooltip title={'True'}>
        <Button
          color={'success'}
          variant={value == true ? 'contained' : 'outlined'}
          onClick={() => onChange(value === true ? undefined : true)}
          size={'small'}
        >
          <Check />
        </Button>
      </Tooltip>
      <Tooltip title={'False'}>
        <Button
          color={'error'}
          variant={value == false ? 'contained' : 'outlined'}
          onClick={() => onChange(value === false ? undefined : false)}
          size={'small'}
        >
          <DoNotDisturb />
        </Button>
      </Tooltip>
    </ButtonGroup>
  );
};
