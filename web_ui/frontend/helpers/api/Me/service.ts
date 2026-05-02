import { Me, MePatch, MyGroup } from './types';
import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import type { UserIdentity } from '@/types';

const MeService = {
  id: 'Me',
  get: async (): Promise<Me> => {
    const response = await fetchApi(() => fetch(`${API_V1_BASE_URL}/me`));
    return await response.json();
  },
  patch: async (patch: MePatch): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/me`, {
          method: 'PATCH',
          body: JSON.stringify(patch),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },
  // /me/password endpoints exist ONLY for "manage what's already set":
  // updatePassword rotates an existing password (caller must supply
  // the current one), clearPassword turns local-password login off.
  // There is no self-service "create" — that path stays admin-only
  // via password-invite redemption so an OIDC-only user can't grow a
  // password that outlives the IdP relationship.
  updatePassword: async (
    currentPassword: string,
    newPassword: string
  ): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/me/password`, {
          method: 'PUT',
          body: JSON.stringify({ currentPassword, newPassword }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },
  clearPassword: async (): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/me/password`, {
          method: 'DELETE',
        })
    );
  },
  // The caller's effective scope set (DB user_scopes ∪ DB group_scopes
  // via membership ∪ config-derived grants ∪ admin implications).
  // Returned as scope-name strings; the catalog at /scopes pairs each
  // name with a human-readable description for display.
  getScopes: async (): Promise<string[]> => {
    const response = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/me/scopes`)
    );
    return await response.json();
  },
  recordAUP: async (version: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/me/aup`, {
          method: 'POST',
          body: JSON.stringify({ version }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },
  getGroups: async (): Promise<MyGroup[]> => {
    const response = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/me/groups`)
    );
    return await response.json();
  },
  leaveGroup: async (groupId: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/me/groups/${groupId}`, {
          method: 'DELETE',
        })
    );
  },
  // List the caller's *secondary* OIDC identities. The primary identity
  // is on the User row itself (returned by get()); secondaries are the
  // ones the user can self-unlink.
  getIdentities: async (): Promise<UserIdentity[]> => {
    const r = await fetchApi(() => fetch(`${API_V1_BASE_URL}/me/identities`));
    return await r.json();
  },
  unlinkIdentity: async (identityId: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/me/identities/${identityId}`, {
          method: 'DELETE',
        })
    );
  },
};

export default MeService;
