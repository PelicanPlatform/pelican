/**
 * API wrappers for manipulating fetched data
 *
 * @module helpers/get
 */

import { Config, ParameterValueRecord } from '@/components/configuration';
import { getConfig as getConfigResponse, getNamespaces } from '@/helpers/api';
import { flattenObject } from '@/app/config/util';
import { Namespace } from '@/index';
import { getObjectValue } from '@/helpers/util';

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
  { namespace: Namespace }[]
> => {
  const response = await getNamespaces();
  const data: Namespace[] = await response.json();
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
