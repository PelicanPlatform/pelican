import {
  Config,
  ConfigMetadata,
  ParameterInputProps,
} from '@/components/Config';

export const getConfigMetadata = async () => {
  try {
    const res = await fetch('/view/data/parameters.json');
    const data = (await res.json()) as ConfigMetadata[];
    const metadata = data.reduce(
      (acc: ConfigMetadata, curr: ConfigMetadata) => {
        const [key, value] = Object.entries(curr)[0];
        acc[key] = value;
        return acc;
      },
      {}
    );

    return metadata;
  } catch {
    return undefined;
  }
};

/**
 * Recursively replace all objects of type { Type: any, Value: any } with the value of Value
 * @param config
 */
export const stripTypes = (config: any) => {
  if (config?.Value !== undefined && config?.Type !== undefined) {
    return config.Value;
  }

  Object.keys(config).forEach((key) => {
    config[key] = stripTypes(config[key]);
  });

  return config;
};

/** Recursively delete the keys that have null values in an object */
export const stripNulls = (config: any) => {
  // If the config is an object then iterate keys otherwise skip
  if (typeof config !== 'object') {
    return config;
  }

  Object.keys(config).forEach((key) => {
    if (config[key] === null) {
      delete config[key];
    } else {
      config[key] = stripNulls(config[key]);
    }
  });

  return config;
};

/**
 * Check if a value is a Config value or a ParameterInputProps value
 * @param value
 */
export const isConfig = (value: ParameterInputProps | Config): boolean => {
  const isConfig = (value as Config)?.Type === undefined;
  return isConfig;
};

/**
 * Sort the config values so that Config values are at the end and in alphabetical order
 * @param a
 * @param b
 */
export function sortConfig(
  a: [string, ParameterInputProps | Config],
  b: [string, ParameterInputProps | Config]
) {
  if (isConfig(a[1]) && !isConfig(b[1])) {
    return 1;
  }
  if (!isConfig(a[1]) && isConfig(b[1])) {
    return -1;
  }
  return a[0].localeCompare(b[0]);
}

/**
 * Delete a key from an object recursively
 * @param obj
 * @param key
 */
export function deleteKey(
  obj: Record<string, any | Record<string, any>>,
  key: string[]
) {
  if (key.length === 1) {
    delete obj[key[0]];
    return;
  } else {
    deleteKey(obj[key[0]], key.slice(1));
    if (Object.keys(obj[key[0]]).length === 0) {
      delete obj[key[0]];
    }
  }
}

type NestedRecord = { [k: string]: any | NestedRecord };

/**
 * Update a value in an object recursively
 * @param obj
 * @param key
 * @param value
 */
export function updateValue(obj: NestedRecord, key: string[], value: any) {
  if (key.length === 1) {
    obj[key[0]] = { ...value, ...obj[key[0]] };
    return;
  } else {
    updateValue(obj[key[0]], key.slice(1), value);
  }
}
