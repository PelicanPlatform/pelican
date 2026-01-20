/**
 * API wrappers for manipulating fetched data
 *
 * @module helpers/get
 */

import { Config, ParameterValueRecord } from '@/components/configuration';
import {
  getConfig as getConfigResponse,
  getDirectorNamespaces as getDirectorNamespacesResponse,
  getDirectorServers as getDirectorServersResponse,
  getNamespaces,
  getFederationDiscrepancy as getFederationDiscrepancyResponse,
} from '@/helpers/api';
import { flattenObject } from '@/app/config/util';
import {
  DirectorNamespace,
  WellKnownConfiguration,
  ServerGeneral,
  MetadataDiscrepancy,
} from '@/types';
import { RegistryNamespace } from '@/index';

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

  const mappedData = data.map((d) => {
    return { namespace: d };
  });

  const sortedData = mappedData.sort((a, b) => {
    return (
      new Date(b.namespace.admin_metadata.updated_at).getTime() -
      new Date(a.namespace.admin_metadata.updated_at).getTime()
    );
  });

  return sortedData;
};

/**
 * Get federation metadata discrepancy status
 */
export const getFederationDiscrepancy =
  async (): Promise<MetadataDiscrepancy> => {
    const response = await getFederationDiscrepancyResponse();
    return (await response.json()) as MetadataDiscrepancy;
  };
