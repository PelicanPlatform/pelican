import {Button, Snackbar, IconButton, Alert, AlertColor} from "@mui/material";
import React from "react";

interface StatusSnackBarAction {
    label: string;
    onClick: () => void;
}

export interface StatusSnackBarProps {
    severity?: AlertColor
    message: string;
    action?: StatusSnackBarAction;
}

export const StatusSnackBar = ({severity, message, action}: StatusSnackBarProps) => {

    const [open, setOpen] = React.useState(true);

    return (
        <Snackbar
            anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
            open={open}
        >
            <Alert
                severity={severity || "info"}
                variant="filled"
                action={
                    action &&
                    <Button
                        color="inherit"
                        size="small"
                        onClick={action.onClick}
                    >
                        {action.label}
                    </Button>
                }
                onClose={() => setOpen(false)}
            >
                {message}
            </Alert>
        </Snackbar>
    )
}

export default StatusSnackBar;
