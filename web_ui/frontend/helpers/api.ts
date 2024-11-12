/**
 * API Helper Functions
 *
 * Strictly return the response from the API, throwing an error if the response is not ok
 */

import { secureFetch } from '@/helpers/login';
import { getErrorMessage } from '@/helpers/util';
import { Namespace } from '@/index';

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
 */
export const getNamespace = async (
  id: string | number
): Promise<Response> => {
  const url = new URL(
    `/api/v1.0/registry_ui/namespaces/${id}`,
    window.location.origin
  );
  return await fetchApi(async () => await fetch(url));
};

export const postGeneralNamespace = async (
  data: Namespace
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
  data: Namespace
): Promise<Response> => {
  return await fetchApi(async () => {
    return secureFetch(`/api/v1.0/registry_ui/namespaces/${data.id}`, {
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
export const optionsNamespaceRegistrationFields = async (): Promise<Response> => {
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
