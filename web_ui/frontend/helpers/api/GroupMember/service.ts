import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import { ApiID, ApiService } from '../types';
import { GroupMember, GroupMemberPost } from '@/helpers/api/GroupMember/types';

type PartialApiService = Required<
  Pick<
    ApiService<GroupMember, GroupMemberPost>,
    'id' | 'getAll' | 'post' | 'delete'
  >
>;

const makeGroupMemberService = (groupId: ApiID): PartialApiService => {
  return {
    id: `Groups/${groupId}/Members`,
    getAll: async () => {
      const response = await fetchApi(() =>
        fetch(`${API_V1_BASE_URL}/groups/${groupId}/members`)
      );
      return await response.json();
    },
    post: async (groupMember) => {
      const response = await fetchApi(
        async () =>
          await secureFetch(`${API_V1_BASE_URL}/groups/${groupId}/members`, {
            method: 'POST',
            body: JSON.stringify(groupMember),
            headers: {
              'Content-Type': 'application/json',
            },
          })
      );
      return await response.json();
    },
    delete: async (id) => {
      await fetchApi(
        async () =>
          await secureFetch(
            `${API_V1_BASE_URL}/groups/${groupId}/members/${id}`,
            {
              method: 'DELETE',
            }
          )
      );
    },
  } as const satisfies ApiService<GroupMember, GroupMemberPost>;
};

export default makeGroupMemberService;
