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
  // No setPassword on the self-service surface by design: passwords are
  // only set via an admin-issued password-invite the user redeems through
  // /invites/redeem/password. See the user/group design contract.
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
    const r = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/me/identities`)
    );
    return await r.json();
  },
  unlinkIdentity: async (identityId: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(
          `${API_V1_BASE_URL}/me/identities/${identityId}`,
          { method: 'DELETE' }
        )
    );
  },
};

export default MeService;
