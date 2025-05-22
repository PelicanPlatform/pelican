import { Alert, AlertProps, AlertTitle } from '@mui/material';
import React, { ReactNode } from 'react';

export interface InlineAlertProps {
  onClose: () => void;
  title?: string;
  autoHideDuration?: number;
  message?: ReactNode | string;
  alertProps?: Omit<AlertProps, 'onClose'>;
}

const InlineAlert = ({
  onClose,
  title,
  autoHideDuration,
  message,
  alertProps,
}: InlineAlertProps) => {
  return (
    <Alert
      onClose={autoHideDuration ? () => {} : onClose}
      severity={alertProps?.severity}
      sx={{ width: '100%' }}
    >
      {title && <AlertTitle>{title}</AlertTitle>}
      {message}
    </Alert>
  );
};

export default InlineAlert;
