
import {User, UserPatch, UserPost} from "./types";
import {secureFetch} from "@/helpers/login";
import {API_V1_BASE_URL} from "../constants";
import {fetchApi} from "@/helpers/api";
import { ApiID, ApiService } from '../types';

const UserService = {
  id: "Users",
  getOne: async (id?: ApiID) => {
    if (!id) return undefined;
    const userResponse = await fetchApi(() => fetch(`${API_V1_BASE_URL}/users/${id}`))
    return await userResponse.json() as User;
  },
  getAll: async () => {
    const usersResponse = await fetchApi(() => fetch(`${API_V1_BASE_URL}/users`))
    return await usersResponse.json() as User[];
  },
  post: async (user: UserPost) => {
    const createdUserResponse = await fetchApi(async () =>
      await secureFetch(`${API_V1_BASE_URL}/users`, {
        method: 'POST',
        body: JSON.stringify(user),
        headers: {
          'Content-Type': 'application/json',
        },
      })
    );
    return await createdUserResponse.json() as User;
  },
  patch: async (id: ApiID, user: UserPatch) => {
    const updatedUserResponse = await fetchApi(async () =>
      await secureFetch(`${API_V1_BASE_URL}/users/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(user),
        headers: {
          'Content-Type': 'application/json',
        },
      })
    )
    return await updatedUserResponse.json() as User;
  },
  delete: async (id: ApiID) => {
    await fetchApi(async () =>
      await secureFetch(`${API_V1_BASE_URL}/users/${id}`, {
        method: 'DELETE',
      })
    );
  }
} satisfies ApiService<User, UserPost, UserPatch>;

export default UserService;
