import { Group, GroupPost, GroupPatch } from './types';
import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import { ApiService } from '../types';

// transferOwnership wraps PUT /groups/:id/ownership. Kept off the
// standard ApiService surface because the backend's admin/owner model
// is richer than patch (ownerId / adminId / adminType all in one
// call); breaking it out keeps the call sites self-documenting.
type GroupApiService = ApiService<Group, GroupPost, GroupPatch> & {
  transferOwnership: (
    id: string,
    body: {
      ownerId?: string;
      adminId?: string;
      adminType?: 'user' | 'group';
    }
  ) => Promise<void>;
};

const GroupService = {
  id: 'Groups',
  getOne: async (id) => {
    const response = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/groups/${id}`)
    );
    return (await response.json()) as Group;
  },
  getAll: async () => {
    const response = await fetchApi(() => fetch(`${API_V1_BASE_URL}/groups`));
    return (await response.json()) as Group[];
  },
  post: async (group: GroupPost) => {
    const response = await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/groups`, {
          method: 'POST',
          body: JSON.stringify(group),
          headers: {
            'Content-Type': 'application/json',
          },
        })
    );
    return (await response.json()) as Group;
  },
  patch: async (id, group) => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/groups/${id}`, {
          method: 'PATCH',
          body: JSON.stringify(group),
          headers: {
            'Content-Type': 'application/json',
          },
        })
    );
  },
  delete: async (id) => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/groups/${id}`, {
          method: 'DELETE',
        })
    );
  },
  // Transfer the group's owner / admin assignments. Only the existing
  // owner OR a system admin can drive this. Nil-omitted fields are
  // left alone server-side; pass an empty string to *clear* OwnerID.
  transferOwnership: async (id, body) => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/groups/${id}/ownership`, {
          method: 'PUT',
          body: JSON.stringify(body),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },
} as const satisfies GroupApiService;

export default GroupService;
