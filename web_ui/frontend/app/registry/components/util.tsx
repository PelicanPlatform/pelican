import { RegistryNamespace } from '@/index';

export const populateKey = (o: any, key: string[], value: any) => {
  let i = 0;
  for (; i < key.length - 1; i++) {
    if (!o[key[i]]) {
      o[key[i]] = {};
    }
    o = o[key[i]];
  }
  o[key[i]] = value;
};

export const calculateKeys = (key: string) => {
  if (key.startsWith('admin_metadata.')) {
    return ['admin_metadata', key.substring(15)];
  }

  if (key.startsWith('custom_fields.')) {
    return ['custom_fields', key.substring(14)];
  }

  return [key];
};

/**
 * Get the value of a key in an object
 * @param o Object to get the value from
 * @param key List of keys to traverse
 */
export const getValue = (
  o: Record<string, any> | undefined,
  key: string[]
): any => {
  if (o === undefined) {
    return undefined;
  }

  if (key.length === 1) {
    return o[key[0]];
  }
  return getValue(o[key[0]], key.slice(1));
};

export const deleteKey = (o: any, key: string[]) => {
  let i = 0;
  for (; i < key.length; i++) {
    if (!o[key[i]]) {
      return;
    }
    o = o[key[i]];
  }
  delete o[key[i]];
  return o;
};

export const namespaceToCache = (data: RegistryNamespace) => {
  // Build the cache prefix
  if (data.prefix.startsWith('/caches/')) {
    return data;
  }

  data['prefix'] = `/caches/${data.prefix}`;
  return data;
};

export const namespaceToOrigin = (data: RegistryNamespace) => {
  // Build the cache prefix
  if (data.prefix.startsWith('/origins/')) {
    return data;
  }

  data['prefix'] = `/origins/${data.prefix}`;
  return data;
};

export const submitNamespaceForm = async (
  data: Partial<RegistryNamespace>,
  toUrl: URL | undefined,
  handleSubmit: (data: Partial<RegistryNamespace>) => Promise<Response>
) => {
  const response = await handleSubmit(data);

  // Clear the form on successful submit
  if (response != undefined) {
    window.location.href = toUrl ? toUrl.toString() : '/view/registry/';
  }
};
