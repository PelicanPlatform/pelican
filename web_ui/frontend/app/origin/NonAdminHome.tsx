'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Box, Grid, Stack, Typography } from '@mui/material';
import {
  CalendarMonth,
  CheckCircleOutline,
  ErrorOutline,
  FolderOpen,
  Groups,
  HelpOutline,
  Launch,
} from '@mui/icons-material';

import FederationOverview from '@/components/FederationOverview';
import ServerName from '@/components/ServerName';

type HealthState = 'loading' | 'ok' | 'degraded' | 'unavailable';

const HealthIndicator = () => {
  const [state, setState] = useState<HealthState>('loading');

  useEffect(() => {
    let cancelled = false;
    const fetchHealth = async () => {
      try {
        const response = await fetch('/api/v1.0/metrics/health');
        if (cancelled) return;
        if (response.status === 401 || response.status === 403) {
          setState('unavailable');
          return;
        }
        if (!response.ok) {
          setState('degraded');
          return;
        }
        const data = await response.json();
        const components = (data?.components ?? {}) as Record<
          string,
          { status?: string }
        >;
        const allOk =
          Object.keys(components).length > 0 &&
          Object.values(components).every((c) => c?.status === 'ok');
        setState(allOk ? 'ok' : 'degraded');
      } catch {
        if (!cancelled) setState('unavailable');
      }
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 60_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const config = {
    loading: {
      icon: <HelpOutline color={'disabled'} />,
      label: 'Checking status…',
    },
    ok: {
      icon: <CheckCircleOutline color={'success'} />,
      label: 'Origin is operational',
    },
    degraded: {
      icon: <ErrorOutline color={'warning'} />,
      label: 'One or more components are degraded',
    },
    unavailable: {
      icon: <HelpOutline color={'disabled'} />,
      label: 'Detailed status is restricted to administrators on this server',
    },
  }[state];

  return (
    <Box
      display={'flex'}
      flexDirection={'row'}
      alignItems={'center'}
      gap={1.5}
      p={2}
      borderRadius={2}
      bgcolor={'background.paper'}
      sx={{ border: 1, borderColor: 'divider' }}
    >
      {config.icon}
      <Typography variant={'body1'}>{config.label}</Typography>
    </Box>
  );
};

const QuickLink = ({
  href,
  text,
  icon,
}: {
  href: string;
  text: string;
  icon: React.ReactNode;
}) => {
  return (
    <Link href={href}>
      <Box
        p={1.5}
        px={2}
        display={'flex'}
        flexDirection={'row'}
        alignItems={'center'}
        gap={1.5}
        bgcolor={'info.light'}
        borderRadius={2}
        mb={1}
      >
        {icon}
        <Typography>{text}</Typography>
        <Box ml={'auto'} display={'flex'}>
          <Launch fontSize={'small'} />
        </Box>
      </Box>
    </Link>
  );
};

const NonAdminHome = () => {
  return (
    <Box width={'100%'}>
      <ServerName defaultName={'Origin'} />
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 6 }}>
          <Typography variant={'h4'} component={'h2'} mb={2}>
            Status
          </Typography>
          <HealthIndicator />
        </Grid>
        <Grid size={{ xs: 12, lg: 6 }}>
          <Typography variant={'h4'} component={'h2'} mb={2}>
            Quick Links
          </Typography>
          <Stack>
            <QuickLink
              href={'/origin/collections/'}
              text={'Collections'}
              icon={<FolderOpen />}
            />
            <QuickLink href={'/groups/'} text={'Groups'} icon={<Groups />} />
            <QuickLink
              href={'/origin/downtime/'}
              text={'Downtime'}
              icon={<CalendarMonth />}
            />
          </Stack>
        </Grid>
        <Grid size={{ xs: 12, lg: 6 }}>
          <FederationOverview />
        </Grid>
      </Grid>
    </Box>
  );
};

export default NonAdminHome;
