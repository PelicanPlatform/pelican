/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import { Box } from '@mui/material';
import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import useSWR from 'swr';

import SettingHeader from '@/app/settings/components/SettingHeader';
import { RestartBox } from '@/app/config/components';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import NavigationConfig, { SettingsShellScopes } from '@/app/navigation';
import { getUser } from '@/helpers/login';
import { hasScope } from '@/index';
import { evaluateOrReturn } from '@/helpers/util';

// The default /settings/ page is the Restart Server surface, which is
// system-admin-only. Users who reach the shell via a scope grant
// (server.user_admin, pelican.log_read; see SettingsShellScopes) need
// somewhere to land other than an "Insufficient privileges" card, so we
// redirect them to the first sub-page they can actually reach.
export default function Home() {
  const router = useRouter();
  const { data: user } = useSWR('getUser', getUser);

  useEffect(() => {
    // Don't redirect until we know who the caller is. Admin gets the
    // native restart page and stays put.
    if (!user?.authenticated) return;
    if (user.role === 'admin') return;

    // Find the first settings-sidebar item the caller can reach that
    // isn't /settings/ itself. Mirrors the visibility check
    // SubNavigation uses so the redirect target always matches what
    // the sidebar shows.
    const target = NavigationConfig.settings.find((item) => {
      if (!('href' in item)) return false;
      const href = evaluateOrReturn(item.href);
      if (href === '/settings/') return false;
      if (!item.allowedRoles && !item.anyScopes) return true;
      const roleOk =
        !!item.allowedRoles &&
        !!user.role &&
        item.allowedRoles.includes(user.role);
      const scopeOk =
        !!item.anyScopes && item.anyScopes.some((s) => hasScope(user, s));
      return roleOk || scopeOk;
    });
    if (target && 'href' in target) {
      router.replace(evaluateOrReturn(target.href));
    }
  }, [user, router]);

  // Admit everyone the shell admits so the redirect fires from inside
  // the protected surface (instead of AuthenticatedContent showing
  // "Insufficient privileges" for the split-second before the effect
  // runs). Non-admins get an empty box while the effect resolves the
  // redirect target; admins see the restart page as before.
  return (
    <AuthenticatedContent
      redirect
      allowedRoles={['admin']}
      anyScopes={SettingsShellScopes}
    >
      {user?.role === 'admin' && (
        <Box width={'100%'}>
          <SettingHeader
            title={'Restart Server'}
            description={
              'Restarting the server will cause a temporary service outage, please use with caution.'
            }
          />
          <RestartBox />
        </Box>
      )}
    </AuthenticatedContent>
  );
}
