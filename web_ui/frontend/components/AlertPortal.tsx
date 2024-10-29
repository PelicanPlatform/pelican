import { Portal } from '@mui/base';
import React, { ReactNode } from 'react';
import {
  Alert,
  AlertProps,
  Snackbar,
  SnackbarProps,
  AlertTitle,
} from '@mui/material';

export interface AlertPortalProps {
  onClose: () => void;
  title?: string;
  autoHideDuration?: number;
  message?: ReactNode | string;
  alertProps?: Omit<AlertProps, 'onClose'>;
  snackBarProps?: SnackbarProps;
}

export const AlertPortal = ({
  onClose,
  title,
  autoHideDuration,
  message,
  alertProps,
  snackBarProps,
}: AlertPortalProps) => {
  if (autoHideDuration) {
    setTimeout(() => onClose(), autoHideDuration);
  }

  return (
    <Portal>
      <Snackbar
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        open={alert !== undefined}
        {...snackBarProps}
      >
        <Alert
          onClose={autoHideDuration ? undefined : onClose}
          severity={alertProps?.severity}
          sx={{ width: '100%' }}
        >
          {title && <AlertTitle>{title}</AlertTitle>}
          {message}
        </Alert>
      </Snackbar>
    </Portal>
  );
};

export default AlertPortal;
