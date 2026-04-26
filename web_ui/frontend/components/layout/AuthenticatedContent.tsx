'use client';

import { Box, BoxProps, Button, Skeleton, Typography } from '@mui/material';
import useSWR from 'swr';
import { getUser } from '@/helpers/login';
import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { hasScope, User } from '@/index';

const Circle = ({ children }: { children: React.ReactNode }) => {
  return (
    <Box
      display={'flex'}
      justifyContent={'center'}
      alignItems={'center'}
      height={'100%'}
      width={'100%'}
    >
      <Box
        padding={6}
        borderRadius={'100%'}
        bgcolor={'primary.light'}
        sx={{ aspectRatio: 1 }}
      >
        <Box
          display={'flex'}
          justifyContent={'center'}
          alignItems={'center'}
          height={'100%'}
          flexDirection={'column'}
        >
          {children}
        </Box>
      </Box>
    </Box>
  );
};

interface AuthenticatedContentProps {
  promptLogin?: boolean;
  redirect?: boolean;
  trustThenValidate?: boolean;
  preloadChildren?: boolean;
  boxProps?: BoxProps;
  allowedRoles?: User['role'][];
  // anyScopes lets a surface admit holders of EITHER any role in
  // allowedRoles OR any scope in this list. Used so e.g.
  // /settings/users/ can be reached by a non-system-admin who holds
  // server.user_admin via group membership. If both allowedRoles and
  // anyScopes are set, EITHER clears the gate (logical OR).
  anyScopes?: string[];
  replace?: boolean;
  children: React.ReactNode;
}

/**
 * AuthenticatedContent is a component that will show the children if the user is authenticated.
 * @param promptLogin If true then the user will be prompted to login if they are not authenticated
 * @param redirect If true then the user will be redirected to the login page if they are not authenticated
 * @param trustThenValidate If true then the user will be shown the content if they are not authenticated but will be validated after
 * @param preloadChildren If true then the children will be preloaded even if the user is not authenticated. This is useful for pages that require authentication but want to show a skeleton while loading.
 * @param boxProps The props to pass to the Box component
 * @param allowedRoles The roles that are allowed to see the content
 * @param replace If true then the
 * @param children The content to show if the user is authenticated
 * @constructor
 */
const AuthenticatedContent = ({
  promptLogin = false,
  redirect = false,
  trustThenValidate = false,
  preloadChildren = false,
  children,
  boxProps,
  allowedRoles,
  anyScopes,
}: AuthenticatedContentProps) => {
  if (redirect && promptLogin) {
    throw new Error('redirect XOR promptLogin must be true');
  }

  const router = useRouter();
  const { data, isValidating, isLoading, error } = useSWR('getUser', getUser, {
    refreshInterval: 1000 * 60,
    revalidateOnMount: true,
  });
  const [pageUrl, setPageUrl] = useState<string>('');

  // Distinguish "not logged in" (redirecting to /login is correct) from
  // "logged in but role mismatch" (redirecting to /login would just send the
  // user back here after a successful login -> infinite loop). Render a clear
  // "insufficient privileges" message in the latter case instead.
  const loggedIn = !!data?.authenticated;
  // requiresAup gates ALL protected content — even role-allowed users
  // must accept first. Treated as a "not yet allowed" state so the
  // children don't mount and fire RequireAUPCompliance-walled API
  // calls during the moment between detection and the
  // /aup-redirect useEffect below.
  const needsAup = !!data?.requiresAup;
  const allowed = useMemo(() => {
    if (!loggedIn) return false;
    if (needsAup) return false;
    if (!allowedRoles && !anyScopes) return true;
    const roleOk =
      !!allowedRoles && !!data?.role && allowedRoles.includes(data.role);
    const scopeOk = !!anyScopes && anyScopes.some((s) => hasScope(data, s));
    return roleOk || scopeOk;
  }, [data, allowedRoles, anyScopes, loggedIn, needsAup]);

  useEffect(() => {
    // Keep pathname as is since backend handles the redirect after logging in and needs the full path
    const path = window.location.pathname + window.location.search;
    const pathUrlEncoded = encodeURIComponent(path);

    setPageUrl(pathUrlEncoded);
  }, []);

  // Only redirect to login when the user isn't logged in at all. A wrong-role
  // user is logged in; sending them back to /login would just bounce them
  // here again on the next successful login.
  useEffect(() => {
    if (!isValidating && !loggedIn && redirect) {
      router.replace('/login/?returnURL=' + pageUrl);
    }
  }, [data, isValidating, loggedIn, pageUrl, redirect, router]);

  // AUP gate. When the server requires an AUP and the caller hasn't
  // accepted the active version, route them to the acceptance page
  // BEFORE the protected children mount. Without this, the children
  // render and start hitting RequireAUPCompliance-walled APIs, which
  // produce a stream of 403 alerts with no obvious way to reach the
  // policy. After accepting, /aup uses the returnURL we passed it to
  // come back here.
  //
  // We only act once we have a fresh `data` (no more validating) AND
  // the caller is logged in — for not-logged-in users the login
  // redirect above already handles them. We use replace, not push, so
  // the gate doesn't pollute the back stack.
  useEffect(() => {
    if (isValidating) return;
    if (!loggedIn) return;
    if (!data?.requiresAup) return;
    // Don't bounce the AUP page back to itself.
    if (
      typeof window !== 'undefined' &&
      window.location.pathname.startsWith('/aup')
    ) {
      return;
    }
    if (!pageUrl) return;
    router.replace(`/aup/?returnURL=${pageUrl}`);
  }, [data, isValidating, loggedIn, pageUrl, router]);

  // If there was a error then print it to the screen
  if (error) {
    return <Circle>{error}</Circle>;
  }

  // If we are allowed in, or if we trust at first while validating, show the content
  if (allowed || (trustThenValidate && (isLoading || isValidating))) {
    return <Box {...boxProps}>{allowed && children}</Box>;
  }

  // If we are loading then show a loader
  if (data === undefined) {
    return (
      <Box
        sx={{
          sx: {
            height: '95vh',
            width: '100%',
            ...boxProps?.sx,
          },
          ...boxProps,
        }}
      >
        <Skeleton variant='rounded' height={'100%'} width={'100%'}>
          {preloadChildren && children}
        </Skeleton>
      </Box>
    );
  }

  // Logged in but the AUP gate is pending. Render a minimal
  // placeholder while the redirect-effect above fires. Without this
  // we'd fall through to the "Insufficient privileges" branch, which
  // is misleading: the user hasn't been denied, they just haven't
  // signed yet.
  if (loggedIn && needsAup) {
    return (
      <Circle>
        <Typography variant={'h5'} align={'center'}>
          Acceptable Use Policy
        </Typography>
        <Typography variant={'subtitle1'} align={'center'}>
          Redirecting to acceptance page…
        </Typography>
      </Circle>
    );
  }

  // Logged in but lacking the required role: show a clear unauthorized
  // message rather than redirecting (which would loop). This applies whether
  // or not promptLogin/redirect are set.
  if (loggedIn && !allowed) {
    return (
      <Circle>
        <Typography variant={'h4'} align={'center'}>
          Insufficient privileges
        </Typography>
        <Typography variant={'subtitle1'} align={'center'}>
          Your account does not have access to this page.
        </Typography>
        <Box pt={4} display={'flex'} gap={1} justifyContent={'center'}>
          <Link href={'/'}>
            <Button variant={'contained'}>Home</Button>
          </Link>
        </Box>
      </Circle>
    );
  }

  // Not logged in and asked to prompt for login: render an inline login CTA.
  if (!loggedIn && promptLogin) {
    return (
      <Circle>
        <Typography variant={'h4'} align={'center'}>
          Unauthorized
        </Typography>
        <Typography variant={'subtitle1'} align={'center'}>
          Login required
        </Typography>
        <Box pt={4}>
          <Link href={`/login/?returnURL=${pageUrl}`}>
            <Button variant={'contained'}>Login</Button>
          </Link>
        </Box>
      </Circle>
    );
  }

  return null;
};

export default AuthenticatedContent;
