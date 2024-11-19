/**
 * API Helper Functions
 *
 * Strictly return the response from the API, throwing an error if the response is not ok
 */

import { secureFetch } from '@/helpers/login';
import { getErrorMessage } from '@/helpers/util';
import { RegistryNamespace } from '@/index';
import { ServerGeneral } from '@/types';

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
      throw Error('Fetch to API Failed', { cause: e });
    } else {
      throw Error('Fetch to API Failed', { cause: e });
    }
  }
}

/**
 * Get config
 */
export const getConfig = async (): Promise<Response> => {
  return fetchApi(async () => await secureFetch('/api/v1.0/config'));
};

/**
 * Deletes a namespace
 * @param id Namespace ID
 */
export const deleteNamespace = async (id: number) => {
  return fetchApi(
    async () =>
      await secureFetch(`/api/v1.0/registry_ui/namespaces/${id}`, {
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
      await secureFetch(`/api/v1.0/registry_ui/namespaces/${id}/approve`, {
        method: 'PATCH',
      })
  );
};

/**
 * Denies a namespace
 * @param id Namespace ID
 */
export const denyNamespace = async (id: number): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(`/api/v1.0/registry_ui/namespaces/${id}/deny`, {
        method: 'PATCH',
      })
  );
};

/**
 * Enables a server on the director
 * @param name Server name
 */
export const allowServer = async (name: string): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(`/api/v1.0/director_ui/servers/allow/${name}`, {
        method: 'PATCH',
      })
  );
};

/**
 * Filters ( Disables ) a server on the director
 * @param name Server name
 */
export const filterServer = async (name: string): Promise<Response> => {
  return fetchApi(
    async () =>
      await secureFetch(`/api/v1.0/director_ui/servers/filter/${name}`, {
        method: 'PATCH',
      })
  );
};

/**
 * Get director servers
 *
 */
export const getDirectorServers = async () => {
  const url = new URL('/api/v1.0/director_ui/servers', window.location.origin);

  return await fetchApi(async () => await fetch(url));
};

/**
 * Get a director server by name
 * @param name Server name
 */
export const getDirectorServer = async (name: string): Promise<Response> => {
  const url = new URL(
    `/api/v1.0/director_ui/servers/${name}`,
    window.location.origin
  );

  return await fetchApi(async () => await fetch(url));
}

/**
 * Get namespaces from director
 */
export const getDirectorNamespaces = async () => {
  const url = new URL(
    '/api/v1.0/director_ui/namespaces',
    window.location.origin
  );

  return await fetchApi(async () => await fetch(url));
};


/**
 * Get namespaces
 */
export const getNamespaces = async (): Promise<Response> => {
  const url = new URL(
    '/api/v1.0/registry_ui/namespaces',
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
    `/api/v1.0/registry_ui/namespaces/${id}`,
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
      await secureFetch('/api/v1.0/registry_ui/namespaces', {
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
    `/api/v1.0/registry_ui/namespaces/${data.id}`,
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
        await fetch('/api/v1.0/registry_ui/namespaces', {
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
      await fetch('/api/v1.0/auth/initLogin', {
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
      await fetch('/api/v1.0/auth/resetLogin', {
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
      await fetch('/api/v1.0/auth/login', {
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
