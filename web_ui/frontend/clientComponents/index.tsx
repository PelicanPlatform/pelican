'use client';

import { LocalizationProvider as IncompatibleLocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterLuxon } from '@mui/x-date-pickers/AdapterLuxon';
import { ReactNode } from 'react';

export const LocalizationProvider = ({ children }: { children: ReactNode }) => {
  return (
    <IncompatibleLocalizationProvider dateAdapter={AdapterLuxon}>
      {children}
    </IncompatibleLocalizationProvider>
  );
};
