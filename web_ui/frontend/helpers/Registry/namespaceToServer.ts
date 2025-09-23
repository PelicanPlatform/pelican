import { RegistryNamespace } from '@/index';
import extendPrefix from '@/helpers/extendPrefix';

/**
 * Extends a registry namespace
 * @param namespace
 */
const extendNamespace = (
  namespace: Omit<RegistryNamespace, 'type' | 'adjustedPrefix'>
): RegistryNamespace => {
  const { type, adjustedPrefix } = extendPrefix(namespace.prefix);
  return {
    ...namespace,
    type,
    adjustedPrefix,
  };
};

export default extendNamespace;
