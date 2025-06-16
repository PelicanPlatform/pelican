import {RegistryNamespace} from "@/index";

/**
 * Extends a registry namespace
 * @param namespace
 */
const extendNamespace = (namespace: Omit<RegistryNamespace, 'type' | 'adjustedPrefix'>) : RegistryNamespace => {

	let type: RegistryNamespace['type'] = 'namespace';
	let adjustedPrefix = undefined;

	// Prefixes that start with /caches/ or /origins/ are considered cache or origin namespaces
	if (namespace.prefix.startsWith('/caches/')) {
		type = 'cache';
		adjustedPrefix = namespace.prefix.replace('/caches/', '');
	} else if (namespace.prefix.startsWith('/origins/')) {
		type = 'origin';
		adjustedPrefix = namespace.prefix.replace('/origins/', '');
	}

	return {
		...namespace,
		type,
		adjustedPrefix
	}
}

export default extendNamespace;
