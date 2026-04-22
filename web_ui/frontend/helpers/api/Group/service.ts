import { Group, GroupPost, GroupPatch } from './types';
import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import { ApiService } from '../types';

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
} as const satisfies ApiService<Group, GroupPost, GroupPatch>;

export default GroupService;
