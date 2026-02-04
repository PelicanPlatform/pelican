'use client';

import { Alert, AlertTitle, Box, Collapse, Typography } from '@mui/material';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import useApiSWR from '@/hooks/useApiSWR';
import { getFederationDiscrepancyConfig } from '@/helpers/api';
import { MetadataDiscrepancy } from '@/types';
import { DateTime } from 'luxon';

interface DiscrepancyItemProps {
  label: string;
  directorValue: string;
  discoveryValue: string;
}

const DiscrepancyItem = ({
  label,
  directorValue,
  discoveryValue,
}: DiscrepancyItemProps) => (
  <Box sx={{ mb: 1 }}>
    <Typography variant='body2' fontWeight='bold'>
      {label}:
    </Typography>
    <Typography variant='body2' sx={{ pl: 2 }}>
      • Director serves: <code>{directorValue}</code>
    </Typography>
    <Typography variant='body2' sx={{ pl: 2 }}>
      • Discovery URL has: <code>{discoveryValue}</code>
    </Typography>
  </Box>
);

const MetadataDiscrepancyAlert = () => {
  const { errorMessage, key, fetcher } = getFederationDiscrepancyConfig;
  const { data: discrepancy } = useApiSWR<MetadataDiscrepancy>(
    errorMessage,
    key,
    fetcher,
    {
      refreshInterval: 10 * 60 * 1000, // Refresh every 10 minutes
      revalidateOnFocus: false,
    }
  );

  // Don't render if:
  // - Still loading
  // - Comparison is disabled (Director is the discovery URL)
  // - No discrepancy detected
  // Note: Errors are automatically handled by useApiSWR
  if (!discrepancy || !discrepancy.enabled || !discrepancy.hasDiscrepancy) {
    return null;
  }

  const lastCheckedFormatted = discrepancy.lastChecked
    ? DateTime.fromISO(discrepancy.lastChecked).toLocaleString(
        DateTime.DATETIME_MED
      )
    : 'Unknown';

  return (
    <Collapse in={discrepancy.hasDiscrepancy}>
      <Alert
        severity='warning'
        icon={<WarningAmberIcon />}
        sx={{
          mb: 3,
          '& .MuiAlert-message': { width: '100%' },
          '& code': {
            backgroundColor: 'rgba(0, 0, 0, 0.08)',
            padding: '2px 6px',
            borderRadius: '4px',
            fontSize: '0.85em',
            wordBreak: 'break-all',
          },
        }}
      >
        <AlertTitle sx={{ fontWeight: 'bold' }}>
          Federation Metadata Discrepancy Detected
        </AlertTitle>
        <Typography variant='body2' sx={{ mb: 2 }}>
          The Director&apos;s federation metadata differs from what the
          Discovery URL ({discrepancy.discoveryUrl}) serves. This may cause
          unexpected behavior for federation clients.
        </Typography>

        {discrepancy.directorUrlMismatch && (
          <DiscrepancyItem
            label='Director Endpoint'
            directorValue={discrepancy.directorUrlMismatch.directorValue}
            discoveryValue={discrepancy.directorUrlMismatch.discoveryValue}
          />
        )}

        {discrepancy.registryUrlMismatch && (
          <DiscrepancyItem
            label='Registry Endpoint'
            directorValue={discrepancy.registryUrlMismatch.directorValue}
            discoveryValue={discrepancy.registryUrlMismatch.discoveryValue}
          />
        )}

        {discrepancy.jwksOverlapChecked && !discrepancy.jwksHasOverlap && (
          <Box sx={{ mb: 1 }}>
            <Typography variant='body2' fontWeight='bold'>
              JWKS Keys:
            </Typography>
            <Typography variant='body2' sx={{ pl: 2 }}>
              • No overlapping public keys found between Director and Discovery
              URL JWKS endpoints. Tokens signed by one may not be verifiable by
              the other.
            </Typography>
          </Box>
        )}

        {discrepancy.jwksError && (
          <Box sx={{ mb: 1 }}>
            <Typography variant='body2' fontWeight='bold'>
              JWKS Check:
            </Typography>
            <Typography variant='body2' sx={{ pl: 2 }}>
              • Could not compare JWKS keys: {discrepancy.jwksError}
            </Typography>
          </Box>
        )}

        <Typography
          variant='caption'
          sx={{ display: 'block', mt: 2, color: 'text.secondary' }}
        >
          Last checked: {lastCheckedFormatted}
        </Typography>
      </Alert>
    </Collapse>
  );
};

export default MetadataDiscrepancyAlert;
