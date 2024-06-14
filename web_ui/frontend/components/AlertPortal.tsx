import { Portal } from '@mui/base';
import React from "react";
import {Alert, SnackbarProps, Snackbar} from "@mui/material";

import {Alert as AlertType} from "@/index";

export interface AlertPortalProps {
    alert?: AlertType;
    onClose: () => void;
    snackBarProps?: SnackbarProps;
}

export const AlertPortal = ({alert, onClose, snackBarProps}: AlertPortalProps) => {
    return (
        <Portal>
            <Snackbar
                anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
                open={alert !== undefined}
                onClose={onClose}
                {...snackBarProps}
            >
                <Alert
                    onClose={onClose}
                    severity={alert?.severity}
                    variant="filled"
                    sx={{ width: '100%' }}
                >
                    {alert?.message}
                </Alert>
            </Snackbar>
        </Portal>
    )
}

export default AlertPortal;
