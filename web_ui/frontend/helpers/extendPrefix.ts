import { RegistryNamespace } from '@/index';

/**
 * Extends a registry namespace
 * @param prefix - Registration prefix, prefixed with /caches/ or /origins/ for cache or origin types, otherwise a namespace
 */
const extendPrefix = (
  prefix: string
): { type: RegistryNamespace['type']; adjustedPrefix: string } => {
  if (prefix.startsWith('/caches/')) {
    return {
      type: 'cache',
      adjustedPrefix: prefix.replace('/caches/', ''),
    };
  } else if (prefix.startsWith('/origins/')) {
    return {
      type: 'origin',
      adjustedPrefix: prefix.replace('/origins/', ''),
    };
  }

  if (prefix.startsWith('/pelican/logging/')) {
    // Logging namespaces keep their full prefix (unlike origins/caches, which
    // are stripped) because these entries are hidden from the UI.
    return {
      type: 'pelican',
      adjustedPrefix: prefix,
    };
  }

  return {
    type: 'namespace',
    adjustedPrefix: prefix,
  };
};

export default extendPrefix;
