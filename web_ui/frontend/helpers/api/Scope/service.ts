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

import { secureFetch } from '@/helpers/login';
import { fetchApi } from '@/helpers/api';
import { API_V1_BASE_URL } from '../constants';

// Wraps the user/group scope CRUD endpoints registered in
// web_ui/ui.go. Catalog + listings are GETs that any authenticated
// caller can make; mutations are admin-walled server-side.

export interface ScopeCatalogEntry {
  /** Machine-readable scope name (e.g. "server.user_admin"). */
  name: string;
  /** Human-readable description, sourced from docs/scopes.yaml at
   * generate time. Omitted when the scope has no description. */
  description?: string;
}

export interface UserScopeGrant {
  userId: string;
  scope: string;
  grantedBy: string;
  authMethod: string;
  authMethodId?: string;
  grantedAt: string;
}

export interface GroupScopeGrant {
  groupId: string;
  scope: string;
  grantedBy: string;
  authMethod: string;
  authMethodId?: string;
  grantedAt: string;
}

const ScopeService = {
  // Catalog of user-grantable scopes — drives the management UI's
  // picker. Any authenticated caller may read; the contents come
  // from token_scopes.UserGrantableScopes.
  catalog: async (): Promise<ScopeCatalogEntry[]> => {
    const r = await fetchApi(() => fetch(`${API_V1_BASE_URL}/scopes`));
    return await r.json();
  },

  // Caller's effective scopes (DB grants + config-derived). Useful
  // for hiding management surfaces a non-admin can't drive.
  myEffective: async (): Promise<string[]> => {
    const r = await fetchApi(() => fetch(`${API_V1_BASE_URL}/me/scopes`));
    return await r.json();
  },

  // Direct user_scopes rows for one user. Admin-walled server-side.
  // NOTE: this is the user's *direct* grants only — group-derived
  // and config-derived scopes are NOT included; for the full
  // effective set call myEffective() (self) or compute server-side.
  listUser: async (userId: string): Promise<UserScopeGrant[]> => {
    const r = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/users/${userId}/scopes`)
    );
    return await r.json();
  },

  grantUser: async (userId: string, scope: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/users/${userId}/scopes`, {
          method: 'POST',
          body: JSON.stringify({ scope }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },

  revokeUser: async (userId: string, scope: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(
          `${API_V1_BASE_URL}/users/${userId}/scopes/${encodeURIComponent(scope)}`,
          { method: 'DELETE' }
        )
    );
  },

  // Direct group_scopes rows for one group. Listing is open to anyone
  // who can see the group; granting/revoking is system-admin-only
  // server-side (granting Server_WebAdmin to a group transitively
  // elevates every member).
  listGroup: async (groupId: string): Promise<GroupScopeGrant[]> => {
    const r = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/groups/${groupId}/scopes`)
    );
    return await r.json();
  },

  grantGroup: async (groupId: string, scope: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/groups/${groupId}/scopes`, {
          method: 'POST',
          body: JSON.stringify({ scope }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },

  revokeGroup: async (groupId: string, scope: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(
          `${API_V1_BASE_URL}/groups/${groupId}/scopes/${encodeURIComponent(scope)}`,
          { method: 'DELETE' }
        )
    );
  },
};

export default ScopeService;
