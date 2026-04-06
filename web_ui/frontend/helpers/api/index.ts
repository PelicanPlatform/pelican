/**
 * API Exports
 */

export { UserService } from './User';
export { GroupService } from './Group';
export { makeGroupMemberService } from './GroupMember';
export * from './types';

/**
 * API Helper Functions
 *
 * Strictly return the response from the API, throwing an error if the response is not ok
 */

import { secureFetch } from '@/helpers/login';
import { getErrorMessage } from '@/helpers/util';
import { RegistryNamespace } from '@/index';
import { API_V1_BASE_URL } from '@/helpers/api/constants';
import { DowntimePost, DowntimeRegistryPost } from '@/types';

/**
 * Wraps an api request with error handling for both the request and the response if error
 * @param fetchRequest The request to make to the api
 * @returns The response from the api
 */
export async function fetchApi(
  fetchRequest: () => Promise<Response>
): Promise<Response> {
  try {
    const response = await fetchRequest();
    if (!response.ok) {
      let alertMessage;
      try {
        alertMessage = await getErrorMessage(response);
      } catch (e) {
        if (e instanceof Error) {
          alertMessage = e.message;
        }
      }
      throw new Error(alertMessage);
    }
    return response;
  } catch (e) {
    if (e instanceof Error) {
      throw Error('Fetch to API Failed', { cause: e.message });
    } else {
      throw Error('Fetch to API Failed', { cause: e });
    }
  }
}

/**
 * Secure API fetch
 */
export const secureApiFetch = async (
  url: string,
  options: RequestInit = {}
): Promise<Response> => {
  return await fetchApi(async () => await secureFetch(url, options));
};

/**
 * Restart the server
 */
export const restartServer = async (): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(`${API_V1_BASE_URL}/restart`, { method: 'POST' })
  );
};

/**
 * Get config
 */
export const getConfig = async (): Promise<Response> => {
  return fetchApi(async () => await secureFetch(`${API_V1_BASE_URL}/config`));
};

/**
 * Deletes a namespace
 * @param id Namespace ID
 */
export const deleteNamespace = async (id: number) => {
  return fetchApi(
    async () =>
      await secureFetch(`${API_V1_BASE_URL}/registry_ui/namespaces/${id}`, {
        method: 'DELETE',
      })
  );
};

/**
 * Approves a namespace
 * @param id Namespace ID
 */
export const approveNamespace = async (id: number): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(
        `${API_V1_BASE_URL}/registry_ui/namespaces/${id}/approve`,
        {
          method: 'PATCH',
        }
      )
  );
};

/**
 * Denies a namespace
 * @param id Namespace ID
 */
export const denyNamespace = async (id: number): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(
        `${API_V1_BASE_URL}/registry_ui/namespaces/${id}/deny`,
        {
          method: 'PATCH',
        }
      )
  );
};

/**
 * Enables a server on the director
 * @param name Server name
 */
export const allowServer = async (name: string): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(
        `${API_V1_BASE_URL}/director_ui/servers/allow/${name}`,
        {
          method: 'PATCH',
        }
      )
  );
};

/**
 * Filters ( Disables ) a server on the director
 * @param name Server name
 */
export const filterServer = async (name: string): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(
        `${API_V1_BASE_URL}/director_ui/servers/filter/${name}`,
        {
          method: 'PATCH',
        }
      )
  );
};

/**
 * Get director servers
 *
 */
export const getDirectorServers = async () => {
  const url = new URL(
    `${API_V1_BASE_URL}/director_ui/servers`,
    window.location.origin
  );

  return await fetchApi(async () => await fetch(url));
};

/**
 * Get a director server by name
 * @param name Server name
 */
export const getDirectorServer = async (name: string): Promise<Response> => {
  const url = new URL(
    `${API_V1_BASE_URL}/director_ui/servers/${name}`,
    window.location.origin
  );

  return await fetchApi(async () => await fetch(url));
};

/**
 * Get namespaces from director
 */
export const getDirectorNamespaces = async () => {
  const url = new URL(
    `${API_V1_BASE_URL}/director_ui/namespaces`,
    window.location.origin
  );

  return await fetchApi(async () => await fetch(url));
};

export const NAMESPACE_KEY = 'getNamespaces';

/**
 * Get namespaces
 */
export const getNamespaces = async (): Promise<Response> => {
  const url = new URL(
    `${API_V1_BASE_URL}/registry_ui/namespaces`,
    window.location.origin
  );

  return await fetchApi(async () => await fetch(url));
};

/**
 * Gets a namespace by ID
 * @param id Namespace ID
 * @param accessToken Access token
 */
export const getNamespace = async (
  id: string | number,
  accessToken?: string
): Promise<Response> => {
  const url = new URL(
    `${API_V1_BASE_URL}/registry_ui/namespaces/${id}`,
    window.location.origin
  );
  if (accessToken) {
    url.searchParams.append('access_token', accessToken);
  }
  return await fetchApi(async () => await fetch(url));
};

export const postGeneralNamespace = async (
  data: RegistryNamespace
): Promise<Response> => {
  return await fetchApi(
    async () =>
      await secureFetch(`${API_V1_BASE_URL}/registry_ui/namespaces`, {
        body: JSON.stringify(data),
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      })
  );
};

export const putGeneralNamespace = async (
  data: RegistryNamespace
): Promise<Response> => {
  // If an access_token is in the URL, add it to the request
  const url = new URL(
    `${API_V1_BASE_URL}/registry_ui/namespaces/${data.id}`,
    window.location.origin
  );
  const accessToken = new URLSearchParams(window.location.search).get(
    'access_token'
  );
  if (accessToken) {
    url.searchParams.append('access_token', accessToken);
  }

  return await fetchApi(async () => {
    return secureFetch(url.toString(), {
      body: JSON.stringify(data),
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    });
  });
};

/**
 * Get registration fields from options for namespace
 */
export const optionsNamespaceRegistrationFields =
  async (): Promise<Response> => {
    return await fetchApi(
      async () =>
        await fetch(`${API_V1_BASE_URL}/registry_ui/namespaces`, {
          method: 'OPTIONS',
        })
    );
  };

/**
 * Initializes a login via terminal code
 */
export const initLogin = async (code: string): Promise<Response> => {
  return await fetchApi(
    async () =>
      await fetch(`${API_V1_BASE_URL}/auth/initLogin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code: code,
        }),
      })
  );
};

/**
 * Reset ( Do initial ) Login
 */
export const resetLogin = async (password: string): Promise<Response> => {
  return await fetchApi(
    async () =>
      await fetch(`${API_V1_BASE_URL}/auth/resetLogin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password: password,
        }),
      })
  );
};

/**
 * Login
 */
export const login = async (
  password: string,
  user: string = 'admin'
): Promise<Response> => {
  return await fetchApi(
    async () =>
      await fetch(`${API_V1_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user: user,
          password: password,
        }),
      })
  );
};

/**
 * Downtime
 */
export const postDowntime = async (
  downtime: DowntimePost | DowntimeRegistryPost
) => {
  return await fetchApi(
    async () =>
      await secureFetch(`${API_V1_BASE_URL}/downtime`, {
        method: 'POST',
        body: JSON.stringify(downtime),
        headers: {
          'Content-Type': 'application/json',
        },
      })
  );
};

export const deleteDowntime = async (id: string) => {
  return await fetchApi(
    async () =>
      await secureFetch(`${API_V1_BASE_URL}/downtime/${id}`, {
        method: 'DELETE',
      })
  );
};

export const putDowntime = async (
  downtimeId: string,
  downtime: DowntimeRegistryPost | DowntimePost
) => {
  return await fetchApi(
    async () =>
      await secureFetch(`${API_V1_BASE_URL}/downtime/${downtimeId}`, {
        method: 'PUT',
        body: JSON.stringify(downtime),
        headers: {
          'Content-Type': 'application/json',
        },
      })
  );
};

/**
 * Get downtime
 */
export const getDowntime = async () => {
  return await fetch(`${API_V1_BASE_URL}/downtime?status=all`);
};

/**
 * Get director downtime
 */
export const getDirectorDowntime = async () => {
  return await fetch(`${API_V1_BASE_URL}/director_ui/downtimes`);
};

/**
 * Get federation metadata discrepancy status
 */
export const getFederationDiscrepancyConfig = {
  errorMessage: 'Could not fetch federation discrepancy status',
  key: `${API_V1_BASE_URL}/director_ui/federation/discrepancy`,
  fetcher: async () =>
    await secureFetch(`${API_V1_BASE_URL}/director_ui/federation/discrepancy`),
};
