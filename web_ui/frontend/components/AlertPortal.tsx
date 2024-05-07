import { Portal } from '@mui/base';
import React from "react";
import {Alert, Snackbar} from "@mui/material";

import {Alert as AlertType} from "@/components/Main";

export interface AlertPortalProps {
    alert?: AlertType;
    onClose: () => void;
}

export const AlertPortal = ({alert, onClose}: AlertPortalProps) => {
    return (
        <Portal>
            <Snackbar
                anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
                open={alert !== undefined}
                onClose={onClose}
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
