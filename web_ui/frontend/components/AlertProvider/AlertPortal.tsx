import { Portal } from '@mui/base';
import React, { ReactNode } from 'react';
import { Snackbar, SnackbarProps } from '@mui/material';
import Alert, { InlineAlertProps } from './Alert';

export interface AlertPortalProps extends InlineAlertProps {
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
  return (
    <Portal>
      <Snackbar
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        open={alert !== undefined}
        {...snackBarProps}
      >
        <Alert
          onClose={onClose}
          title={title}
          autoHideDuration={autoHideDuration}
          message={message}
          alertProps={alertProps}
        />
      </Snackbar>
    </Portal>
  );
};

export default AlertPortal;
