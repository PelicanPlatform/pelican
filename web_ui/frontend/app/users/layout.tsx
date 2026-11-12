/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

// User administration used to sit under /settings/users, inside the
// administration shell. It is now a primary destination in its own right
// (alongside /groups/), which is why it lives at the top level: a page that
// is not in the administration menu should not be inside the administration
// path, or you land somewhere the visible menu cannot represent.
//
// Deliberately no SubNavigation here -- rendering the administration menu is
// what shrinks the rail, and a primary destination should not do that.
//
// Admitted to system admins AND user-admins (server.user_admin, possibly
// granted via group membership). Per-row edit/delete affordances stay gated
// by IsSystemAdminUserID at the API layer, so a user-admin can manage
// non-admin accounts but cannot escalate against an existing admin.

import { Main, PaddedContent } from '@/components/layout';
import { Navigation } from '@/components/layout/Navigation';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

export const metadata = {
  title: {
    template: '%s | Users',
    default: 'Users',
  },
  description: 'User administration',
};

export default function UsersLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Navigation sharedPage={true}>
      <Main>
        <AuthenticatedContent
          redirect
          trustThenValidate
          allowedRoles={['admin']}
          anyScopes={['server.user_admin']}
          boxProps={{ width: '100%' }}
        >
          <PaddedContent>{children}</PaddedContent>
        </AuthenticatedContent>
      </Main>
    </Navigation>
  );
}
