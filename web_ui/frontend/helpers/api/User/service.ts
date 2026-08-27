import { User, UserPatch, UserPost } from './types';
import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import { ApiService } from '../types';
import type { UserIdentity } from '@/types';

// No setPassword on the admin surface: admins do not learn or set
// passwords. To onboard a local-password account, mint a password-set
// invite (InviteService.createPasswordInvite) and hand the link to the
// user. Self-service password change for the calling user lives on
// MeService.setPassword. Admins CAN clear a password (disable login
// without learning it) via clearPassword().
type UserApiService = ApiService<User, UserPost, UserPatch> & {
  clearPassword: (id: string) => Promise<void>;
  // clearAUP forces this single user back through the AUP-acceptance
  // workflow without rotating the active AUP version (which would
  // re-prompt every user on the server). Admin-only.
  clearAUP: (id: string) => Promise<void>;
  listIdentities: (id: string) => Promise<UserIdentity[]>;
  unlinkIdentity: (userId: string, identityId: string) => Promise<void>;
};

const UserService = {
  id: 'Users',
  getOne: async (id): Promise<User> => {
    const userResponse = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/users/${id}`)
    );
    return await userResponse.json();
  },
  getAll: async (): Promise<User[]> => {
    const usersResponse = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/users`)
    );
    return await usersResponse.json();
  },
  post: async (user): Promise<User> => {
    const createdUserResponse = await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/users`, {
          method: 'POST',
          body: JSON.stringify(user),
          headers: {
            'Content-Type': 'application/json',
          },
        })
    );
    return await createdUserResponse.json();
  },
  patch: async (id, user): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/users/${id}`, {
          method: 'PATCH',
          body: JSON.stringify(user),
          headers: {
            'Content-Type': 'application/json',
          },
        })
    );
  },
  delete: async (id): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/users/${id}`, {
          method: 'DELETE',
        })
    );
  },
  // Admin: clear a user's local password. There is no admin-side
  // "set" — to issue new credentials, mint a password-set invite via
  // InviteService.createPasswordInvite(). Idempotent.
  clearPassword: async (id: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/users/${id}/password`, {
          method: 'DELETE',
        })
    );
  },
  // Admin: blank a user's recorded AUP acceptance. Their next page
  // load will re-prompt them through the AUP workflow. Distinct from
  // editing the AUP itself (which forces every user on the server to
  // re-accept).
  clearAUP: async (id: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/users/${id}/aup`, {
          method: 'DELETE',
        })
    );
  },
  listIdentities: async (id: string): Promise<UserIdentity[]> => {
    const r = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/users/${id}/identities`)
    );
    return await r.json();
  },
  unlinkIdentity: async (userId: string, identityId: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(
          `${API_V1_BASE_URL}/users/${userId}/identities/${identityId}`,
          { method: 'DELETE' }
        )
    );
  },
} as const satisfies UserApiService;

export default UserService;
