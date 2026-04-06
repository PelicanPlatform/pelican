import { User, UserPatch, UserPost } from './types';
import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import { ApiService } from '../types';

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
} as const satisfies ApiService<User, UserPost, UserPatch>;

export default UserService;
