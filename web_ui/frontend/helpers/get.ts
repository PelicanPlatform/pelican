/**
 * API wrappers for manipulating fetched data
 *
 * @module helpers/get
 */

import { Config, ParameterValueRecord } from '@/components/configuration';
import {
  getDirectorNamespaces as getDirectorNamespacesResponse,
  getDirectorServers as getDirectorServersResponse,
  getConfig as getConfigResponse,
  getNamespaces,
} from '@/helpers/api';
import { flattenObject } from '@/app/config/util';
import { DirectorNamespace } from '@/types';
import { RegistryNamespace } from '@/index';
import { getObjectValue } from '@/helpers/util';
import { ServerGeneral } from '@/types';

/**
 * Director Getters
 */

/**
 * Get and sort director servers
 */
export const getDirectorServers = async () => {
  const response = await getDirectorServersResponse();
  const responseData: ServerGeneral[] = await response.json();
  responseData.sort((a, b) => a.name.localeCompare(b.name));
  return responseData;
};

/**
 * Get and sort director namespaces
 */
export const getDirectorNamespaces = async () => {
  const response = await getDirectorNamespacesResponse();
  const responseData: DirectorNamespace[] = await response.json();
  responseData.sort((a, b) => a.path.localeCompare(b.path));
  return responseData;
};

export const getConfig = async (): Promise<ParameterValueRecord> => {
  let response = await getConfigResponse();
  let data = await response.json();
  let flatData = flattenObject(data);
  return flatData;
};

/**
 * Get extended namespaces
 */
export const getExtendedNamespaces = async (): Promise<
  { namespace: RegistryNamespace }[]
> => {
  const response = await getNamespaces();
  const data: RegistryNamespace[] = await response.json();
  data.sort((a, b) => (a.id > b.id ? 1 : -1));
  data.forEach((namespace) => {
    if (namespace.prefix.startsWith('/caches/')) {
      namespace.type = 'cache';
      namespace.prefix = namespace.prefix.replace('/caches/', '');
    } else if (namespace.prefix.startsWith('/origins/')) {
      namespace.type = 'origin';
      namespace.prefix = namespace.prefix.replace('/origins/', '');
    } else {
      namespace.type = 'namespace';
    }
  });

  return data.map((d) => {
    return { namespace: d };
  });
};

/**
 * Get federation URLs
 */
export const getFederationUrls = async () => {
  try {
    const response = await getConfigResponse();
    const responseData = (await response.json()) as Config;

    const federationUrls = UrlData.map(({ key, text }) => {
      let url = getObjectValue<string>(responseData, key);
      if (url && !url?.startsWith('http://') && !url?.startsWith('https://')) {
        url = 'https://' + url;
      }

      return {
        text,
        url,
      };
    });

    return federationUrls;
  } catch (e) {
    console.error(e);
    return [];
  }
};
const UrlData = [
  { key: ['Federation', 'NamespaceUrl'], text: 'Namespace Registry' },
  { key: ['Federation', 'DirectorUrl'], text: 'Director' },
  { key: ['Federation', 'RegistryUrl'], text: 'Registry' },
  {
    key: ['Federation', 'TopologyNamespaceUrl'],
    text: 'Topology Namespace',
  },
  { key: ['Federation', 'DiscoveryUrl'], text: 'Discovery' },
  { key: ['Federation', 'JwkUrl'], text: 'JWK' },
];
