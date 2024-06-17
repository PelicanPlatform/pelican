import {Button, ButtonGroup, IconButton, Tooltip} from '@mui/material';
import {Check, DoNotDisturb, HorizontalRule} from "@mui/icons-material";


interface BooleanToggleButtonProps {
    label: string;
    value?: boolean;
    onChange: (value?: boolean) => void;
}

export const BooleanToggleButton = ({label, value, onChange}: BooleanToggleButtonProps) => {
    return (
        <ButtonGroup
            aria-label={label}
        >
            <Button disabled size={"small"}>
                {label}
            </Button>
            <Tooltip title={"Either"}>
                <Button
                    variant={value == undefined ? "contained" : "outlined"}
                    onClick={() => onChange(undefined)}
                    size={"small"}
                >
                    <HorizontalRule/>
                </Button>
            </Tooltip>
            <Tooltip title={"True"}>
                <Button
                    color={"success"}
                    variant={value == true ? "contained" : "outlined"}
                    onClick={() => onChange(true)}
                    size={"small"}
                >
                    <Check/>
                </Button>
            </Tooltip>
            <Tooltip title={"False"}>
                <Button
                    color={"error"}
                    variant={value == false ? "contained" : "outlined"}
                    onClick={() => onChange(false)}
                    size={"small"}
                >
                    <DoNotDisturb/>
                </Button>
            </Tooltip>
        </ButtonGroup>
    )
}
